"""Authentication middleware.

A pure Starlette ``BaseHTTPMiddleware`` so it applies to every route on
the app. The previous Beforeware-based implementation only wrapped
FastHTML's ``@rt``-decorated handlers; routes registered directly on
``app.routes`` would have bypassed auth entirely.
"""

import logging

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from . import startup
from .services import web_sessions

logger = logging.getLogger(__name__)

# Routes that don't require authentication. /api/* is owned by the
# FastAPI sub-app and short-circuited in dispatch() below regardless of
# this set.
PUBLIC_ROUTES = {"/login", "/login/submit", "/favicon.ico"}

# Static-asset URL prefixes that bypass auth. Trailing-slash form is
# load-bearing — a bare "/css" prefix would also exempt a hypothetical
# future route like "/cssadmin", which CLAUDE.md treats as a hard rule
# violation ("never add unprotected routes").
_STATIC_PREFIXES = ("/static/", "/css/", "/js/", "/img/")

# Shown in the page's error banner when a background (HTMX) action meets an
# ended login. The page is kept, so what the user typed is not lost.
ENDED_LOGIN_MESSAGE_HTML = (
    '<div class="error-message">Your login has ended, so this was not saved. '
    'What you typed is still on this page. '
    '<a href="/login" target="_blank" rel="noopener">Log in again</a> '
    'in a new tab, then try again here.</div>'
)


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _banner(body: str, status: int) -> HTMLResponse:
    """An error for the page's error banner (see static/js/app.js)."""
    return HTMLResponse(body, status_code=status, headers={
        "HX-Retarget": "#error-banner", "HX-Reswap": "innerHTML",
        "Cache-Control": "no-store"})


def _resolve(ticket: str):
    return web_sessions.resolve(
        startup.get_web_session_repo(), startup.get_local_user_repo(), ticket,
        web_sessions.utcnow(), web_sessions.current_policy())


class AuthMiddleware(BaseHTTPMiddleware):
    """Session-based authentication for HTML routes.

    Sets ``request.scope["auth"]`` to the authenticated User on protected
    paths; redirects to /login when no session is present. Skips public
    paths, static assets, and the entire /api/* surface (owned by the
    FastAPI sub-app's own Bearer-auth dependency).
    """

    async def dispatch(self, request: Request, call_next):
        # The path the router matches. Never request.url.path: Starlette
        # rebuilds that from the Host header, so a Host like "x/api" made
        # every page look like /api/... and skipped the login.
        path = request.scope["path"]

        # Browsers never send "." or ".." segments, and a hop that collapsed
        # them after this check would turn an exempt prefix (/api/, /static/)
        # into a protected page.
        if any(segment in (".", "..") for segment in path.split("/")):
            return PlainTextResponse("Bad Request", status_code=400)

        # Public paths and static assets: pass through with no auth.
        if path in PUBLIC_ROUTES or path.startswith(_STATIC_PREFIXES):
            request.scope["auth"] = None
            return await call_next(request)

        # API surface is handled by the mounted FastAPI sub-app. Skipping
        # here avoids running both the session check and the Bearer-auth
        # check on every API request.
        if path.startswith("/api/") or path == "/api":
            request.scope["auth"] = None
            return await call_next(request)

        # Session-backed HTML routes. The cookie holds only a ticket; the
        # login itself lives server-side (services/web_sessions.py).
        try:
            sess = request.session
        except AssertionError:
            # No SessionMiddleware installed (e.g., tests that mount this
            # middleware in isolation). Treat as anonymous.
            sess = {}

        ticket = sess.get("sid")
        try:
            user = await run_in_threadpool(_resolve, ticket) if ticket else None
        except Exception:
            # Never let a request through on a guess.
            logger.exception("Login check failed: database unavailable")
            if _is_htmx(request):
                return _banner('<div class="error-message">Database unavailable.</div>', 503)
            return PlainTextResponse("Database unavailable", status_code=503)

        if user is None:
            sess.clear()
            if _is_htmx(request):
                return _banner(ENDED_LOGIN_MESSAGE_HTML, 401)
            return RedirectResponse("/login", status_code=303)

        request.scope["auth"] = user
        return await call_next(request)
