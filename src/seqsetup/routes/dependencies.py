"""FastAPI dependencies — load + check guards consumed via ``Depends(...)``.

Clinical-safety contract (codified per Section 7 of the design spec):

* ``require_admin_dep`` RAISES on failure. Router-level
  ``dependencies=[Depends(...)]`` ignores return values; only raises
  short-circuit. The HTML-aware ``HTTPException`` handler renders the
  403 as an HTML fragment, not the FastAPI default JSON.

* ``get_editable_run`` waits for the run's turn (``hold_run_turn``:
  one request edits a run at a time), then loads + checks an editable run,
  and that the request's user holds its edit lock.
  ``get_editable_run_to_read`` makes the same checks without a turn, for a
  route that saves nothing; ``wait_for_run_turn`` lets Mark Ready wait for
  the saves in line without holding a turn itself. ``get_draft_run`` skips the lock
  check: it is only for the four ``/edit-lock`` routes that take, give
  back or keep the lock (tests/integration/test_edit_lock.py lists every
  run-changing route that does not use ``get_editable_run``). Mutation
  handlers then enter the ``saving_run`` context manager to persist;
  reviewers grep ``with saving_run(`` to enumerate every mutation
  handler.

* ``get_exportable_run`` allows access for export endpoints; READY +
  ARCHIVED only.

* ``_load_and_check_editable`` is the shared primitive; the dep wraps
  it for FastAPI use. Both call the same function so unit tests on the
  primitive cover both consumers.
"""

import logging
from contextlib import contextmanager
from typing import AsyncIterator, Callable, Iterator

from fastapi import Depends, HTTPException, Request
from starlette.datastructures import FormData

from ..context import AppContext
from ..models.sequencing_run import RunStatus, SequencingRun
from ..models.user import UserRole
from ..repositories.base import ConflictError
from ..services import edit_locks, run_turns
from ..services.audit_log import audit
from ..services.edit_locks import EditLockRefused
from ..services.run_history import record_run_updated
from ..startup import get_app_context
from .utils import get_username


# ---------------------------------------------------------------------------
# Context dep — replaces closure-captured ``ctx`` in the per-module
# ``register(app, ctx)`` factories.
# ---------------------------------------------------------------------------


def get_ctx() -> AppContext:
    """Return the singleton AppContext. Cached at startup; the dep just
    fetches it each request."""
    return get_app_context()


# ---------------------------------------------------------------------------
# Admin guard — raises, never returns. FastAPI ignores return values of
# router-level deps; only raises short-circuit.
# ---------------------------------------------------------------------------


def require_admin_dep(request: Request) -> None:
    """Raise 403 if the authenticated user isn't an admin."""
    user = request.scope.get("auth")
    if not user or user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")


# ---------------------------------------------------------------------------
# Editable-run guards — shared primitive + dep wrapper + save CM.
# ---------------------------------------------------------------------------


def _load_and_check_editable(run_id: str, run_repo) -> SequencingRun:
    """Load the run by id; raise 404 if missing, 403 if not DRAFT."""
    run = run_repo.get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status != RunStatus.DRAFT:
        raise HTTPException(status_code=403, detail="Run is not in draft status and cannot be edited")
    return run


async def hold_run_turn(run_id: str) -> AsyncIterator[None]:
    """FastAPI dep: wait for the run's turn, on the event loop, and hold it
    until the route function returns (``services/run_turns.py``). Routes run
    on worker threads, so one person's two quick saves to a run would
    otherwise overlap and the second lose the version check. A turn that does
    not come is a 409 that changes nothing."""
    try:
        async with run_turns.turn(run_id):
            yield
    except run_turns.TurnNotGiven as refused:
        raise ConflictError(str(refused)) from None


def get_editable_run(
    run_id: str,
    request: Request,
    ctx: AppContext = Depends(get_ctx),
    _turn: None = Depends(hold_run_turn, scope="function"),
) -> SequencingRun:
    """FastAPI dep: load + check the editable run, and that the request's
    user holds its edit lock -- after the run's turn has come, so nothing
    else edits it between this load and the save. Mutation handlers then
    enter ``with saving_run(run, ctx, request):`` to persist."""
    run = _load_and_check_editable(run_id, ctx.run_repo)
    require_edit_lock(run, ctx, request)
    return run


def get_editable_run_to_read(
    run_id: str,
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> SequencingRun:
    """FastAPI dep: ``get_editable_run`` without the run's turn, for a route
    that saves nothing -- a preview, the LIMS lists. Such a route may wait on
    the LIMS for as long as its socket timeout allows per read; holding the
    turn meanwhile made the person's own saves wait, and be refused after
    ``TURN_WAIT_SECONDS`` (fresh review of 057748e, P3-2)."""
    run = _load_and_check_editable(run_id, ctx.run_repo)
    require_edit_lock(run, ctx, request)
    return run


async def wait_for_run_turn(run_id: str) -> None:
    """FastAPI dep: wait until the saves already in line for the run are
    done, without holding a turn after them -- for Mark Ready, which then
    loads the run they left. It may run for minutes, so it holds no turn
    itself; started from the run before a save still landing, it ran every
    check and drew the report, then lost the version check to the person's
    own edit (fresh review of 057748e, P3-1)."""
    try:
        async with run_turns.turn(run_id):
            pass
    except run_turns.TurnNotGiven as refused:
        raise ConflictError(str(refused)) from None


def get_draft_run(
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> SequencingRun:
    """FastAPI dep: load a Draft run, whoever holds its edit lock -- for the
    routes that take, give back or keep the lock itself."""
    return _load_and_check_editable(run_id, ctx.run_repo)


def require_edit_lock(run: SequencingRun, ctx: AppContext, request: Request) -> None:
    """Raise 409 unless the request's user holds the run's edit lock: one
    person edits a Draft at a time (services/edit_locks.py; the user's
    decision, 2026-10-13)."""
    try:
        edit_locks.require(ctx.edit_lock_repo, run.id, get_username(request))
    except EditLockRefused as e:
        raise ConflictError(str(e))


def get_archivable_run(
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> SequencingRun:
    """Load a run for archive/delete; raise 404 if missing.

    Unlike `get_editable_run` (which requires DRAFT), this dep does NOT
    check status — archive is valid from READY, and delete from an empty
    DRAFT or (admins only) ARCHIVED. The handler is responsible for the
    state-machine check (`check_status_transition` for archive, explicit
    status/role guard for delete).
    """
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


def get_exportable_run(
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> SequencingRun:
    """Load a run that's eligible for export.

    Raises HTTPException(404) if the run doesn't exist.
    Raises HTTPException(403) if the run is in DRAFT status — exports
    only available for READY and ARCHIVED runs.
    """
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status not in (RunStatus.READY, RunStatus.ARCHIVED):
        raise HTTPException(
            status_code=403,
            detail="Exports are only available for ready or archived runs",
        )
    return run


@contextmanager
def saving_run(
    run: SequencingRun,
    ctx: AppContext,
    request: Request,
) -> Iterator[SequencingRun]:
    """Context manager: on successful exit, ``touch + save`` the run, then
    record a change-history entry for the diff.

    On exception, do NOT save and do NOT record — the exception propagates and
    the run stays untouched. The post-save history block is exception-guarded so
    a diff/append failure can never 500 a clinical edit that already persisted
    (history is best-effort; failures are logged + audited).
    """
    before = run.to_dict()
    try:
        yield run
    except BaseException:
        raise
    else:
        actor = get_username(request)
        run.touch(updated_by=actor)
        ctx.run_repo.save(run)
        try:
            record_run_updated(ctx, run, before, actor)
        except Exception:
            logging.getLogger(__name__).error(
                "Failed to record run history for %s", run.id, exc_info=True
            )
            audit("run.history.record_failed", actor=actor, target=run.id,
                  outcome="failure", reason="append_error")


# ---------------------------------------------------------------------------
# The submitted form, read on the event loop. Reading a request's body is the
# one thing a route needs the loop for; with this dep the route itself is a
# plain ``def`` that Starlette runs on a worker thread (review F9).
# ---------------------------------------------------------------------------


async def submitted_form(request: Request) -> FormData:
    """FastAPI dep: the request's form, as ``await request.form()`` reads it."""
    return await request.form()


def submitted_form_with_parts_up_to(max_part_size: int) -> Callable:
    """A ``submitted_form`` that reads each field up to ``max_part_size``
    bytes, as ``request.form(max_part_size=...)`` does."""
    async def read(request: Request) -> FormData:
        return await request.form(max_part_size=max_part_size)
    return read


# ---------------------------------------------------------------------------
# HTMX detection — typed dep instead of header sniff.
# ---------------------------------------------------------------------------


def is_htmx_request(request: Request) -> bool:
    """True if the request was made by HTMX (sets ``HX-Request: true``)."""
    return request.headers.get("HX-Request", "").lower() == "true"
