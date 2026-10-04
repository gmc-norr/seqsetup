"""Admin → Deleted runs (spec 2026-09-28 group 2a, F16).

GET /admin/deleted-runs                    — the list
GET /admin/deleted-runs/{copy_id}          — one kept copy, read only
GET /admin/deleted-runs/{copy_id}/history  — that run's change history, paged

What is listed is decided by services.deleted_runs from each copy's state and
the live runs collection. Nothing here changes a copy or a run.

Admin-only via router-level require_admin_dep.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ...context import AppContext
from ...models.deleted_run import DeletedRun
from ...models.sequencing_run import SequencingRun
from ...services.deleted_runs import NOT_CONFIRMED, visible_copy, visible_rows
from ...templating import render
from ..dependencies import get_ctx, require_admin_dep
from ..utils import sanitize_string
from ...utils.clock import local_time


router = APIRouter(
    tags=["admin-deleted-runs"],
    dependencies=[Depends(require_admin_dep)],
)

_HISTORY_PAGE = 50
_ID_MAX = 64
_NOT_FOUND = "No deleted run with that id."


def _minute(iso: Optional[str]) -> str:
    """'2026-09-28T12:05:31.123' (stored, UTC) -> '2026-09-28 14:05 CEST' in
    the display zone."""
    return local_time(datetime.fromisoformat(iso)) if iso else ""


def _find(ctx: AppContext, copy_id: str) -> Optional[tuple[DeletedRun, dict]]:
    if ctx.deleted_run_repo is None:
        return None
    return visible_copy(ctx.deleted_run_repo, ctx.run_repo, sanitize_string(copy_id, _ID_MAX))


@router.get("/admin/deleted-runs", response_class=HTMLResponse)
def deleted_runs_page(request: Request, ctx: AppContext = Depends(get_ctx)) -> Response:
    """GET /admin/deleted-runs — the list, newest first."""
    rows = []
    if ctx.deleted_run_repo is not None:
        rows = [
            {**row, "when": _minute(row.get("finished_at") or row["started_at"])}
            for row in visible_rows(ctx.deleted_run_repo, ctx.run_repo)
        ]
    return render(request, "admin/deleted_runs.html", {
        "rows": rows,
        "any_not_confirmed": any(row["shown_state"] == NOT_CONFIRMED for row in rows),
    })


@router.get("/admin/deleted-runs/{copy_id}", response_class=HTMLResponse)
def deleted_run_page(copy_id: str, request: Request, ctx: AppContext = Depends(get_ctx)) -> Response:
    """GET /admin/deleted-runs/{copy_id} — one kept copy, read only."""
    found = _find(ctx, copy_id)
    if found is None:
        return Response(_NOT_FOUND, status_code=404)
    copy, row = found
    return render(request, "admin/deleted_run.html", {
        "copy": copy,
        "run": SequencingRun.from_dict(copy.run),
        "shown_state": row["shown_state"],
        "shown_deleted_by": row["shown_deleted_by"],
        "deleted_when": _minute(row.get("finished_at") or row["started_at"]),
    })


@router.get("/admin/deleted-runs/{copy_id}/history", response_class=HTMLResponse)
def deleted_run_history(
    copy_id: str,
    request: Request,
    before_ts: str = "",
    before_id: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /admin/deleted-runs/{copy_id}/history — the run's change history,
    with the same paging rules as /runs/{run_id}/history."""
    found = _find(ctx, copy_id)
    if found is None:
        return Response(_NOT_FOUND, status_code=404)
    copy, _row = found
    # A keyset cursor is both-or-neither; half a cursor is malformed input.
    if bool(before_ts) != bool(before_id):
        return Response("Invalid pagination cursor", status_code=400)
    entries = []
    if ctx.run_history_repo is not None:
        entries = ctx.run_history_repo.list_by_run(
            copy.run_id,
            limit=_HISTORY_PAGE + 1,
            before_ts=before_ts or None,
            before_id=before_id or None,
        )
    has_more = len(entries) > _HISTORY_PAGE
    entries = entries[:_HISTORY_PAGE]
    next_ts = next_id = None
    if has_more and entries:
        next_ts, next_id = entries[-1].cursor()
    return render(request, "runs/_history_list.html", {
        "run": SequencingRun.from_dict(copy.run),
        "entries": entries,
        "next_ts": next_ts,
        "next_id": next_id,
        "show_baseline": (not has_more) and (not entries or entries[-1].kind != "created"),
        "history_url": f"/admin/deleted-runs/{copy.copy_id}/history",
    })
