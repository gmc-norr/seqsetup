"""FastAPI dependencies — the DI-native replacements for the old
function-style guards in ``utils.py``.

The old shapes (``require_admin(req) -> Response | None``,
``check_run_editable(run) -> Response | None``) coexist in ``utils.py``
until Phase 4 — per-route migrations switch to these as they happen.

Clinical-safety contract (codified per Section 7 of the design spec):

* ``require_admin_dep`` RAISES on failure. Router-level
  ``dependencies=[Depends(...)]`` ignores return values; only raises
  short-circuit. The HTML-aware ``HTTPException`` handler renders the
  403 as an HTML fragment, not the FastAPI default JSON.

* ``get_editable_run`` is the load + check half of the old
  ``editable_run_handler`` decorator. The save half is the
  ``saving_run`` context manager — handlers explicitly enter the
  ``with`` block to persist mutations.

* ``_load_and_check_editable`` is the shared primitive; the dep wraps
  it for FastAPI use. Both call the same function so unit tests on the
  primitive cover both consumers.
"""

from contextlib import contextmanager
from typing import Iterator

from fastapi import Depends, HTTPException, Request

from ..context import AppContext
from ..models.sequencing_run import RunStatus, SequencingRun
from ..models.user import UserRole
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


def get_editable_run(
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> SequencingRun:
    """FastAPI dep: load + check the editable run. Mutation handlers
    then enter ``with saving_run(run, ctx, request):`` to persist."""
    return _load_and_check_editable(run_id, ctx.run_repo)


def get_archivable_run(
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> SequencingRun:
    """Load a run for archive/delete; raise 404 if missing.

    Unlike `get_editable_run` (which requires DRAFT), this dep does NOT
    check status — archive is valid from DRAFT and READY, and delete is
    valid from ARCHIVED. The handler is responsible for the state-machine
    check (`check_status_transition` for archive, explicit status guard
    for delete).
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
    only available for READY and ARCHIVED runs (mirrors the legacy
    `check_run_exportable(run)` guard from routes/utils.py).
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
    *,
    reset_validation: bool = True,
) -> Iterator[SequencingRun]:
    """Context manager: on successful exit, ``touch + save`` the run.
    On exception, do NOT save — the exception propagates as the
    response and the run stays untouched in the repo.

    Args:
        reset_validation: forwarded to ``run.touch(...)``. Default True
            because most mutations (sample edits, name change, etc.)
            invalidate any prior validation approval. Pass False for
            status-only transitions (archive, status change,
            validation approve/unapprove) where preserving
            ``validation_approved`` is the whole point of the touch
            call. Four current callsites use False — preserved by
            opting in.

    Single audit point for the load→check→mutate→touch→save invariant.
    Reviewers grep ``with saving_run(`` to enumerate every mutation
    handler.
    """
    try:
        yield run
    except BaseException:
        raise
    else:
        run.touch(reset_validation=reset_validation, updated_by=get_username(request))
        ctx.run_repo.save(run)


# ---------------------------------------------------------------------------
# HTMX detection — typed dep instead of header sniff.
# ---------------------------------------------------------------------------


def is_htmx_request(request: Request) -> bool:
    """True if the request was made by HTMX (sets ``HX-Request: true``)."""
    return request.headers.get("HX-Request", "").lower() == "true"
