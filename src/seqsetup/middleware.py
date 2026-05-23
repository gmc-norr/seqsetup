"""Authentication middleware.

A pure Starlette ``BaseHTTPMiddleware`` so it applies to every route on
the app. The previous Beforeware-based implementation only wrapped
FastHTML's ``@rt``-decorated handlers; routes registered directly on
``app.routes`` would have bypassed auth entirely.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

from .models.user import User

# Routes that don't require authentication. /api/* is owned by the
# FastAPI sub-app and short-circuited in dispatch() below regardless of
# this set.
PUBLIC_ROUTES = {"/login", "/login/submit", "/favicon.ico"}

# Static-asset URL prefixes that bypass auth. Trailing-slash form is
# load-bearing — a bare "/css" prefix would also exempt a hypothetical
# future route like "/cssadmin", which CLAUDE.md treats as a hard rule
# violation ("never add unprotected routes").
_STATIC_PREFIXES = ("/static/", "/css/", "/js/", "/img/")


class AuthMiddleware(BaseHTTPMiddleware):
    """Session-based authentication for HTML routes.

    Sets ``request.scope["auth"]`` to the authenticated User on protected
    paths; redirects to /login when no session is present. Skips public
    paths, static assets, and the entire /api/* surface (owned by the
    FastAPI sub-app's own Bearer-auth dependency).
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

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

        # Session-backed HTML routes.
        try:
            sess = request.session
        except AssertionError:
            # No SessionMiddleware installed (e.g., tests that mount this
            # middleware in isolation). Treat as anonymous.
            sess = {}

        user_data = sess.get("user")
        if not user_data:
            return RedirectResponse("/login", status_code=303)

        try:
            request.scope["auth"] = User.from_dict(user_data)
        except (KeyError, ValueError):
            # Invalid session payload — drop it and force re-login.
            sess.clear()
            return RedirectResponse("/login", status_code=303)

        return await call_next(request)
