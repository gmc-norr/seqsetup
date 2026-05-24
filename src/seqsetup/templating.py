"""Jinja2 templating for HTML routes.

The HTML side of the app is migrating off FastHTML (which uses Python
FT components) onto Starlette + Jinja2 + HTMX. This module owns the
single Jinja2Templates instance and the global context every template
needs (current user, cache-busting asset versions, etc.).

API routes are not the concern here — those live in ``seqsetup.api``
and use FastAPI's auto-generated JSON responses.

Template context contract:
    Every render() call injects one key before merging the caller's
    context:
      - ``user``  — the authenticated User object, or None on public
        pages (login/logout, /favicon.ico). Templates that show
        per-user state must guard with ``{% if user %}``.

    Cache-busting for static assets uses the ``asset_url`` Jinja
    filter (registered below). Use as ``{{ 'css/app.css' | asset_url }}``
    which expands to ``/css/app.css?v=<hash>``.

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
import logging
from pathlib import Path
from typing import Any, Optional

from jinja2_fragments.fastapi import Jinja2Blocks
from starlette.requests import Request
from starlette.responses import HTMLResponse


logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent
TEMPLATES_DIR = _PROJECT_ROOT / "templates"
STATIC_DIR = _PROJECT_ROOT / "static"


def _asset_hash(rel_path: str) -> str:
    """Stable short hash of a static asset for cache-busting query strings."""
    full = STATIC_DIR / rel_path
    if full.exists():
        return hashlib.md5(full.read_bytes()).hexdigest()[:8]
    # Missing-asset warning: a template references a static file that
    # doesn't exist. Browsers will 404 the URL — silent in production
    # before this warning. Per CLAUDE.md "Never silently discard data."
    logger.warning("asset_url: missing static file %s", rel_path)
    return "0"


templates = Jinja2Blocks(directory=str(TEMPLATES_DIR))


def _asset_url(rel_path: str) -> str:
    """``'js/foo.js' | asset_url`` → ``'/js/foo.js?v=abc12345'``.

    Hash recomputed at template render — fine, the static dir is small
    and these hashes are computed only during HTML rendering, not for
    every request to the static file itself.
    """
    h = _asset_hash(rel_path)
    return f"/{rel_path}?v={h}"


templates.env.filters["asset_url"] = _asset_url


def render(
    request: Request,
    template: str,
    context: Optional[dict] = None,
    *,
    block_name: Optional[str] = None,
    status_code: int = 200,
    headers: Optional[dict] = None,
):
    """Render a full template, or one named ``{% block %}`` from it.

    ``block_name=None`` → full page (the ``{% extends "_app_shell.html" %}``
    chain). ``block_name="foo"`` → just the ``{% block foo %}`` contents,
    no shell — for HTMX swap fragments.
    """
    ctx = dict(context or {})
    # ``request.scope["auth"]`` is set by the auth beforeware. On public
    # routes (PUBLIC_ROUTES in middleware.py) it's None — templates that
    # use ``user`` MUST guard with ``{% if user %}``.
    ctx.setdefault("user", request.scope.get("auth"))

    # HTML routes carry session-scoped data (current user, draft run
    # state, error messages, etc.). Intermediate-proxy caching of any of
    # those is wrong — pin Cache-Control to no-store unless the caller
    # explicitly overrides. (Asset routes go through StaticFiles, not
    # this helper, so this only applies to rendered HTML.)
    merged_headers = {"Cache-Control": "no-store"}
    if headers:
        merged_headers.update(headers)

    return templates.TemplateResponse(
        request,
        template,
        ctx,
        block_name=block_name,
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
