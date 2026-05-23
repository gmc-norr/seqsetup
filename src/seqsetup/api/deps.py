"""FastAPI dependencies for the API sub-app.

These replace the hand-rolled checks in the FastHTML middleware. They
read from request scope (so the existing middleware stack keeps working
unchanged) and raise HTTP exceptions instead of returning ad-hoc Response
objects — FastAPI turns those into the right status codes and the
exception handler logs/audits centrally.
"""

from fastapi import HTTPException, Request, status

from ..context import AppContext
from ..models.api_token import ApiToken
from ..rate_limit import client_identity, get_api_limiter
from ..services.audit_log import audit


def make_bearer_auth(ctx: AppContext):
    """Build a FastAPI dependency that resolves the Bearer token.

    The dependency closes over the AppContext — symmetric with how the
    FastAPI handlers read ctx.run_repo. Tests get isolation via the
    fresh_app fixture (full module reload), production never swaps the
    context at runtime, so early-binding is safe.

    Returns an ApiToken on success, raises 401 on failure. Also rate-limits
    per-IP *before* the bcrypt check so a credential-stuffing probe with
    rotating tokens can't burn CPU.
    """
    def _dep(request: Request) -> ApiToken:
        # Per-IP rate limit — same limiter used by the legacy middleware.
        ip = client_identity(request)
        ok, retry = get_api_limiter().allow(f"api-ip:{ip}")
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry)},
            )

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization header",
                headers={"WWW-Authenticate": 'Bearer realm="seqsetup"'},
            )
        token_str = auth_header[7:]
        token = ctx.api_token_repo.verify_token(token_str)
        if token is None:
            audit("api.auth.failure", actor="", outcome="failure", ip=ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Bearer token",
                headers={"WWW-Authenticate": 'Bearer realm="seqsetup"'},
            )
        # Stash in scope for middleware/handlers that read it the old way.
        request.scope["api_token"] = token
        return token

    return _dep


def api_actor(token: ApiToken) -> str:
    """Stable identity string for audit events keyed off an authenticated token."""
    return f"api-token:{token.id}"
