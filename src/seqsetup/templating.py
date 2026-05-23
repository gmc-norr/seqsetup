"""Jinja2 templating for HTML routes.

The HTML side of the app is migrating off FastHTML (which uses Python
FT components) onto Starlette + Jinja2 + HTMX. This module owns the
single Jinja2Templates instance and the global context every template
needs (current user, cache-busting asset versions, etc.).

API routes are not the concern here — those live in ``seqsetup.api``
and use FastAPI's auto-generated JSON responses.

Template context contract:
    Every render() call injects two keys before merging the caller's
    context:
      - ``user``  — the authenticated User object, or None on public
        pages (login/logout, /favicon.ico). Templates that show
        per-user state must guard with ``{% if user %}``.
      - ``asset_versions`` — dict mapping static-asset paths to
        cache-busting hash strings. Use as
        ``/css/app.css?v={{ asset_versions['css/app.css'] }}``.

Transitional FT helpers (``ft_to_html`` / ``ft_response`` / ``ft_page_response``):
    During the migration, complex FT-component subtrees (e.g., the
    validation page's heatmaps + color balance subtrees, totaling
    ~1000 LOC) are kept as Python functions. Routes use ``ft_response``
    to render an FT subtree as an HTTP response, or ``ft_page_response``
    to slot one into the standard app shell. Once a component has been
    converted to a Jinja2 template, the call site moves to ``render``
    and the FT helper is dropped.
"""

import hashlib
from pathlib import Path
from typing import Any, Optional

from starlette.requests import Request
from starlette.responses import HTMLResponse
# Imported from starlette directly — Jinja2Templates is a Starlette type
# that FastAPI re-exports. Importing from starlette matches the "HTML side
# is plain Starlette + Jinja2" framing.
from starlette.templating import Jinja2Templates


_PROJECT_ROOT = Path(__file__).parent
TEMPLATES_DIR = _PROJECT_ROOT / "templates"
STATIC_DIR = _PROJECT_ROOT / "static"


def _asset_hash(rel_path: str) -> str:
    """Stable short hash of a static asset for cache-busting query strings."""
    full = STATIC_DIR / rel_path
    if full.exists():
        return hashlib.md5(full.read_bytes()).hexdigest()[:8]
    return "0"


# Computed once at import — same lifecycle as the previous FastHTML setup.
ASSET_VERSIONS = {
    "css/app.css": _asset_hash("css/app.css"),
    "js/app.js": _asset_hash("js/app.js"),
}


templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def render(
    request: Request,
    template: str,
    context: Optional[dict] = None,
    status_code: int = 200,
    headers: Optional[dict] = None,
):
    """Render a Jinja2 template with the standard context applied.

    The wrapping helper exists so every HTML response gets the same
    globals (current user, asset versions) without each handler having
    to remember to inject them.
    """
    ctx = dict(context or {})
    # ``request.scope["auth"]`` is set by the auth beforeware. On public
    # routes (PUBLIC_ROUTES in middleware.py) it's None — templates that
    # use ``user`` MUST guard with ``{% if user %}``.
    ctx.setdefault("user", request.scope.get("auth"))
    ctx.setdefault("asset_versions", ASSET_VERSIONS)

    # HTML routes carry session-scoped data (current user, draft run
    # state, error messages, etc.). Intermediate-proxy caching of any of
    # those is wrong — pin Cache-Control to no-store unless the caller
    # explicitly overrides. (Asset routes go through StaticFiles, not
    # this helper, so this only applies to rendered HTML.)
    merged_headers = {"Cache-Control": "no-store"}
    if headers:
        merged_headers.update(headers)

    # New Starlette signature: (request, name, context, ...). The previous
    # (name, {"request": request, ...}) form is deprecated.
    return templates.TemplateResponse(
        request,
        template,
        ctx,
        status_code=status_code,
        headers=merged_headers,
    )


def ft_to_html(component: Any) -> str:
    """Render a FastHTML FT component (or tuple of components) to an HTML string.

    Transitional helper for routes that have been migrated to Starlette
    but whose FT components haven't yet been ported to Jinja2 templates.
    Once a component is converted, its callers stop using this helper.
    """
    # Lazy import — once every FT component is gone, this module no longer
    # needs python-fasthtml at all.
    from fasthtml.common import to_xml
    if isinstance(component, (list, tuple)):
        return "".join(to_xml(c) for c in component)
    return to_xml(component)


def ft_response(
    component: Any,
    status_code: int = 200,
    headers: Optional[dict] = None,
) -> HTMLResponse:
    """HTMLResponse for an HTMX fragment rendered from an FT component.

    For full-page responses (with the app shell) use ``ft_page_response``.
    """
    merged_headers = {"Cache-Control": "no-store"}
    if headers:
        merged_headers.update(headers)
    return HTMLResponse(
        ft_to_html(component),
        status_code=status_code,
        headers=merged_headers,
    )


def ft_page_response(
    request: Request,
    component: Any,
    *,
    page_title: str = "SeqSetup",
    active_route: str = "",
    status_code: int = 200,
    headers: Optional[dict] = None,
) -> HTMLResponse:
    """Full-page response: render an FT component into the standard app shell.

    Uses the ``_app_shell_raw.html`` template so the FT-rendered content
    slots inside the same header/sidebar every Jinja2 page uses. The
    component's HTML is marked ``|safe`` in the template — the caller is
    responsible for ensuring it's well-formed.
    """
    return render(
        request,
        "_app_shell_raw.html",
        {
            "page_title": page_title,
            "active_route": active_route,
            "raw_content_html": ft_to_html(component),
        },
        status_code=status_code,
        headers=headers,
    )
