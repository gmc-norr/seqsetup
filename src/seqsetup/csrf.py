"""CSRF defense: Origin/Host check on state-changing requests.

Sits alongside SameSite=Strict on the session cookie. Strict-mode SameSite
already prevents browsers from attaching the session cookie to cross-site
POSTs, which blocks the classical CSRF attack. This middleware adds a
second layer for residual cases (older browsers, subdomain takeovers,
defense-in-depth):

  On POST / PUT / PATCH / DELETE the request must carry an Origin header
  whose scheme+host matches the request Host (or one of the explicitly
  configured trusted hosts).

API routes authenticated by Bearer token are exempt — they aren't
cookie-driven and the Origin header may legitimately be absent on
non-browser clients (curl, scripts).

To allow additional Origin values (e.g., behind a load balancer that
rewrites Host), set the SEQSETUP_TRUSTED_ORIGINS env var to a comma-
separated list of full origins (e.g., "https://seqsetup.example.com").
"""

import logging
import os
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse


logger = logging.getLogger(__name__)


_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _load_trusted_origins() -> set[str]:
    raw = os.environ.get("SEQSETUP_TRUSTED_ORIGINS", "")
    return {o.strip() for o in raw.split(",") if o.strip()}


def _normalise_origin(scheme: str, host: str) -> str:
    """Return a normalised "scheme://host" with the default port stripped.

    Browsers send Origin without a port when it's the scheme default
    (80 for http, 443 for https). Host headers may include the port.
    Normalise both sides so the comparison is meaningful.
    """
    if not scheme or not host:
        return ""
    host_only = host.split(":", 1)[0] if ":" in host else host
    port_str = host.split(":", 1)[1] if ":" in host else ""
    default_port = (scheme == "https" and port_str == "443") or (
        scheme == "http" and port_str == "80"
    )
    if not port_str or default_port:
        return f"{scheme}://{host_only}"
    return f"{scheme}://{host_only}:{port_str}"


def check_origin_against_host(
    method: str,
    path: str,
    origin_header: str,
    host_header: str,
    request_scheme: str,
    trusted_origins: set[str],
    authorization_header: str = "",
) -> tuple[bool, str]:
    """Pure-function core: should this request be allowed?

    Returns (allowed, reason). Reason is empty on allow.
    """
    if method not in _STATE_CHANGING_METHODS:
        return True, ""

    # API surface is Bearer-token authenticated and not cookie-driven, so
    # CSRF doesn't apply when a Bearer token is being presented. We exempt
    # ``/api/*`` only in that case — a future ``/api/*`` route that ever
    # touched the session cookie without a Bearer header would otherwise
    # silently inherit the bypass. With this gate, such a route would be
    # protected by the standard Origin check.
    if path.startswith("/api/") and authorization_header.lower().startswith("bearer "):
        return True, ""

    if not origin_header:
        return False, "Missing Origin header on state-changing request"

    parsed = urlsplit(origin_header)
    origin_norm = _normalise_origin(parsed.scheme, parsed.netloc)

    if origin_norm in trusted_origins:
        return True, ""

    expected = _normalise_origin(request_scheme, host_header or "")
    if expected and origin_norm == expected:
        return True, ""

    return False, (
        f"Origin {origin_header!r} does not match Host {host_header!r} "
        f"or any SEQSETUP_TRUSTED_ORIGINS entry"
    )


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """Reject state-changing requests whose Origin doesn't match Host."""

    def __init__(self, app, trusted_origins: set[str] = None):
        super().__init__(app)
        # Resolve at construction so a test can pass an explicit set without
        # having to manipulate the env var.
        self._trusted_origins = (
            trusted_origins if trusted_origins is not None else _load_trusted_origins()
        )

    async def dispatch(self, request: Request, call_next):
        allowed, reason = check_origin_against_host(
            method=request.method,
            path=request.url.path,
            origin_header=request.headers.get("origin", ""),
            host_header=request.headers.get("host", ""),
            request_scheme=request.url.scheme,
            trusted_origins=self._trusted_origins,
            authorization_header=request.headers.get("authorization", ""),
        )
        if not allowed:
            logger.warning(
                "Rejected CSRF candidate request: %s %s — %s",
                request.method,
                request.url.path,
                reason,
            )
            return PlainTextResponse("Forbidden", status_code=403)
        return await call_next(request)
