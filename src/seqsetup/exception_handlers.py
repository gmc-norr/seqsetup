"""HTML-aware exception handlers — overrides the FastAPI default JSON
responses for HTML routes so the "no JSON in HTML routes" rule holds.

The ``/api/*`` sub-app keeps the FastAPI default JSON behaviour — those
ARE JSON endpoints.

Three handlers:

  - ``RequestValidationError`` (422): Pydantic form validation. For
    HTMX requests, returns an HTML fragment with ``HX-Reswap``/
    ``HX-Retarget`` headers so the error lands in a form-errors slot.
    For non-HTMX, returns a friendly error page.

  - ``HTTPException``: any ``raise HTTPException(...)`` from a dep or
    handler. Replaces the FastAPI default ``JSONResponse``. Returns an
    HTML fragment (HTMX-aware) or a full HTML page.

  - ``ConflictError``: optimistic-lock conflict from
    ``SequencingRun.save``. Always 409 with a plain-text-in-HTML body.

**Security: every user/exception-controlled string is HTML-escaped
before interpolation.** Field names come from Pydantic and are
developer-controlled, but ``HTTPException.detail`` and ``ConflictError``
messages can be set by ANY code path including ones that might (now or
later) include user-supplied data. Defence in depth — escape always.
"""

import html

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import HTMLResponse

from .repositories.base import ConflictError


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _is_api_path(request: Request) -> bool:
    """``/api/*`` paths are handled by the sub-app, not the host."""
    return request.url.path == "/api" or request.url.path.startswith("/api/")


def _error_fragment(message: str) -> str:
    """Build an HTML error fragment. ``message`` is HTML-escaped.

    All exception handler responses go through this helper so the
    escape is centralized.
    """
    return f'<div class="error-message">{html.escape(message)}</div>'


async def request_validation_handler(request: Request, exc: RequestValidationError):
    """Form-validation 422 → HTML fragment for HTMX, page for non-HTMX.

    Does NOT echo the offending input value (security: minimises help
    for an attacker fingerprinting validation rules).
    """
    if _is_api_path(request):
        # Let FastAPI's default JSON handler take over for the API.
        from fastapi.exception_handlers import request_validation_exception_handler
        return await request_validation_exception_handler(request, exc)

    # Build a minimal field-list message without echoing values.
    fields = []
    for err in exc.errors():
        loc = err.get("loc", ())
        # Skip the body/form prefix; we only want the field name.
        field_name = ".".join(str(p) for p in loc if p not in ("body", "form")) or "?"
        fields.append(field_name)
    field_list = ", ".join(sorted(set(fields))) or "input"
    body = _error_fragment(f"Validation error: {field_list} invalid.")

    headers = {"Cache-Control": "no-store"}
    if _is_htmx(request):
        # HTMX clients: re-target the form-errors slot, inner-swap.
        headers["HX-Retarget"] = "#form-errors"
        headers["HX-Reswap"] = "innerHTML"
        return HTMLResponse(content=body, status_code=422, headers=headers)

    # Non-HTMX (rare for HTML routes): render the same minimal page.
    page = f"<!DOCTYPE html><html><body>{body}</body></html>"
    return HTMLResponse(content=page, status_code=422, headers=headers)


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Any ``raise HTTPException(...)`` → HTML fragment, NOT JSON.

    Replaces FastAPI's default JSON response so 403/404 etc. raised
    from deps don't surface as raw JSON in the browser.
    """
    if _is_api_path(request):
        from fastapi.exception_handlers import http_exception_handler as default_handler
        return await default_handler(request, exc)

    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    body = _error_fragment(detail)
    headers = {"Cache-Control": "no-store"}
    if _is_htmx(request):
        headers["HX-Retarget"] = "#error-banner"
        headers["HX-Reswap"] = "innerHTML"
        return HTMLResponse(content=body, status_code=exc.status_code, headers=headers)

    page = f"<!DOCTYPE html><html><body>{body}</body></html>"
    return HTMLResponse(content=page, status_code=exc.status_code, headers=headers)


async def conflict_handler(request: Request, exc: ConflictError):
    """Optimistic-lock conflict → 409 with the user-facing message."""
    return HTMLResponse(
        content=_error_fragment(str(exc)),
        status_code=409,
        headers={"Cache-Control": "no-store"},
    )


def install(app):
    """Register all three handlers on the FastAPI app."""
    app.add_exception_handler(RequestValidationError, request_validation_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(ConflictError, conflict_handler)
