"""Admin application-logs viewer page.

GET  /admin/logs           — full page (or fragment on HX-Request)
POST /admin/logs/clear     — wipe captured logs; HTMX fragment swap
                              into #logs-page

The filter form GETs /admin/logs with ?level= and ?search= query
params; HX-Request → block_name="logs_page" so the same handler
serves both the full-page (no HX-Request) and the fragment (HX swap).
This is the canonical jinja2-fragments dual-render pattern.

Admin-only via router-level require_admin_dep.
"""

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ...context import AppContext
from ...services.audit_log import audit
from ...templating import render
from ..dependencies import get_ctx, is_htmx_request, require_admin_dep
from ..utils import get_username, sanitize_string


router = APIRouter(
    tags=["admin-logs"],
    dependencies=[Depends(require_admin_dep)],
)


@router.get("/admin/logs", response_class=HTMLResponse)
def admin_logs(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
    level: Optional[str] = None,
    search: Optional[str] = None,
    is_htmx: bool = Depends(is_htmx_request),
) -> Response:
    """GET /admin/logs — page or fragment.

    Query params come in via FastAPI's request body parsing; they're
    sanitised here defensively (the log_capture API already filters
    by level enum, but search is free-text — clamp it).
    """
    from ...services.log_capture import get_captured_logs, get_log_stats

    # Normalize: empty/None → no filter (match prior semantics).
    level_param = sanitize_string(level or "", 16) or None
    search_param = sanitize_string(search or "", 256) or None

    entries = get_captured_logs(level=level_param, search=search_param, limit=200)
    stats = get_log_stats()

    ctx_dict = {
        "entries": entries,
        "stats": stats,
        "level_filter": level_param or "",
        "search_filter": search_param or "",
        "message": "",
    }
    if is_htmx:
        return render(request, "admin/logs.html", ctx_dict, block_name="logs_page")
    return render(request, "admin/logs.html", ctx_dict)


@router.post("/admin/logs/clear", response_class=HTMLResponse)
def clear_logs(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/logs/clear — wipe captured logs; HTMX fragment swap."""
    from ...services.log_capture import clear_captured_logs, get_log_stats

    clear_captured_logs()
    audit("logs.cleared", actor=get_username(request), target="log_buffer")
    return render(
        request,
        "admin/logs.html",
        {
            "entries": [],
            "stats": get_log_stats(),
            "level_filter": "",
            "search_filter": "",
            "message": "Logs cleared",
        },
        block_name="logs_page",
    )
