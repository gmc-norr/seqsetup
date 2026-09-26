"""Admin audit-trail page.

GET /admin/audit — full page, or the audit_page fragment on HX-Request.

Shows the permanent audit trail (AuditEventRepository), newest first, 100
per page, narrowed by the filter form's query parameters. Read-only: nothing
here changes or deletes an event.

Admin-only via router-level require_admin_dep.
"""

import json
from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ...context import AppContext
from ...models.audit_event import FIELD_CAPS
from ...templating import render
from ..dependencies import get_ctx, is_htmx_request, require_admin_dep
from ..utils import sanitize_string


router = APIRouter(
    tags=["admin-audit"],
    dependencies=[Depends(require_admin_dep)],
)

_PAGE = 100
_CURSOR_MAX = 64


def _day_start(text: str, plus_days: int = 0) -> str:
    """'YYYY-MM-DD' -> canonical timestamp of that UTC day's start, moved by
    ``plus_days``. Raises ValueError on any other shape, OverflowError past
    the last representable day."""
    return (datetime.strptime(text, "%Y-%m-%d") + timedelta(days=plus_days)).isoformat()


@router.get("/admin/audit", response_class=HTMLResponse)
def admin_audit(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
    event: str = "",
    actor: str = "",
    target: str = "",
    date_from: str = "",
    date_to: str = "",
    before_ts: str = "",
    before_id: str = "",
    is_htmx: bool = Depends(is_htmx_request),
) -> Response:
    """GET /admin/audit — page or fragment."""
    # Each box is cut to its field's stored length, so any stored value can
    # be searched for.
    filters = {
        "event": sanitize_string(event, FIELD_CAPS["event"]),
        "actor": sanitize_string(actor, FIELD_CAPS["actor"]),
        "target": sanitize_string(target, FIELD_CAPS["target"]),
        "date_from": sanitize_string(date_from, 10),
        "date_to": sanitize_string(date_to, 10),
    }
    before_ts = sanitize_string(before_ts, _CURSOR_MAX)
    before_id = sanitize_string(before_id, _CURSOR_MAX)
    # A keyset cursor is both-or-neither. Half a cursor is malformed input —
    # refuse it rather than silently answer with the first page.
    if bool(before_ts) != bool(before_id):
        return Response("Invalid pagination cursor", status_code=400)

    error = ""
    from_ts = to_ts = None
    try:
        if filters["date_from"]:
            from_ts = _day_start(filters["date_from"])
        if filters["date_to"]:
            to_ts = _day_start(filters["date_to"], plus_days=1)
    except (ValueError, OverflowError):
        error = "Dates must be real dates, written like 2026-09-26."

    events = []
    if not error and ctx.audit_event_repo is not None:
        events = ctx.audit_event_repo.search(
            limit=_PAGE + 1,
            event_prefix=filters["event"] or None,
            actor=filters["actor"] or None,
            target=filters["target"] or None,
            from_ts=from_ts,
            to_ts=to_ts,
            before_ts=before_ts or None,
            before_id=before_id or None,
        )
    has_more = len(events) > _PAGE
    events = events[:_PAGE]

    older_url = ""
    if has_more:
        next_ts, next_id = events[-1].cursor()
        query = {k: v for k, v in filters.items() if v}
        query.update(before_ts=next_ts, before_id=next_id)
        older_url = "/admin/audit?" + urlencode(query)

    rows = [
        {
            "time": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "actor": e.actor,
            "event": e.event,
            "target": e.target,
            "outcome": e.outcome,
            "details": json.dumps(e.details, indent=1, sort_keys=True) if e.details else "",
        }
        for e in events
    ]
    ctx_dict = {"rows": rows, "filters": filters, "error": error, "older_url": older_url}
    if is_htmx:
        return render(request, "admin/audit.html", ctx_dict, block_name="audit_page")
    return render(request, "admin/audit.html", ctx_dict)
