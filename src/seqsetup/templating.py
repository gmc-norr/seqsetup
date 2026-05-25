"""Jinja2 templating for HTML routes.

All page rendering is via Jinja2 + jinja2-fragments.

This module owns the single Jinja2Templates instance and the global
context every template needs (current user, cache-busting asset
versions, etc.).

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
"""

import hashlib
import logging
from pathlib import Path
from typing import Optional

from jinja2_fragments.fastapi import Jinja2Blocks
from starlette.requests import Request


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


