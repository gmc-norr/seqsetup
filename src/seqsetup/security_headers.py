"""Security response-header middleware.

Sets headers that defend against common browser-side attacks:

- X-Content-Type-Options: nosniff — disables MIME sniffing
- X-Frame-Options: DENY — blocks framing (clickjacking)
- Referrer-Policy: same-origin — limits referrer leakage to other origins
- Strict-Transport-Security — pins HTTPS (only when served over TLS)
- Cross-Origin-Opener-Policy: same-origin — isolates browsing context
- Cross-Origin-Resource-Policy: same-origin — restricts cross-origin loads

These cover the audit's H5 finding without being intrusive to existing
in-app behaviour (no Content-Security-Policy added here — that would
require a separate inventory of inline-script use in components/).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def apply_security_headers(response: Response, is_https: bool) -> None:
    """Set security headers on the given response in-place.

    Strict-Transport-Security is only set when the request was over HTTPS —
    sending HSTS over plaintext is meaningless and confuses browsers in dev.
    """
    for name, value in _SECURITY_HEADERS.items():
        # Don't clobber a value an inner handler already set deliberately.
        response.headers.setdefault(name, value)
    if is_https:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Starlette ASGI middleware that applies the security headers above."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        apply_security_headers(response, is_https=request.url.scheme == "https")
        return response
