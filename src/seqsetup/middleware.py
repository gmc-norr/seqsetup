"""Authentication middleware for the FastHTML application."""

from fasthtml.common import Beforeware
from starlette.responses import RedirectResponse, Response

from .models.user import User

# Routes that don't require authentication
PUBLIC_ROUTES = {"/login", "/login/submit", "/favicon.ico", "/api/docs", "/api/openapi.json", "/api/openapi.yaml"}


def make_auth_beforeware(get_api_token_repo_fn):
    """Create authentication beforeware.

    Args:
        get_api_token_repo_fn: Callable that returns the ApiTokenRepository instance.

    Returns:
        Beforeware instance for FastHTML app.
    """

    def auth_beforeware(req, sess):
        """
        Check authentication on protected routes.

        Adds `auth` attribute to request scope with User object or None.
        Redirects to login if not authenticated on protected routes.
        """
        path = req.url.path

        # Check if route is public
        if path in PUBLIC_ROUTES or path.startswith(("/static", "/css", "/js", "/img")):
            req.scope["auth"] = None
            return

        # API routes require Bearer token authentication
        if path.startswith("/api/"):
            auth_header = req.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                token_str = auth_header[7:]
                api_token = get_api_token_repo_fn().verify_token(token_str)
                if api_token:
                    req.scope["auth"] = None
                    req.scope["api_token"] = api_token
                    return
            return Response("Unauthorized", status_code=401)

        # Check session for authenticated user
        user_data = sess.get("user")
        if not user_data:
            return RedirectResponse("/login", status_code=303)

        # Restore User object from session
        try:
            user = User.from_dict(user_data)
            req.scope["auth"] = user
        except (KeyError, ValueError):
            # Invalid session data, clear and redirect
            sess.clear()
            return RedirectResponse("/login", status_code=303)

    return Beforeware(auth_beforeware, skip=[r"/favicon\.ico", r"/static/.*"])
