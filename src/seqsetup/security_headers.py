"""Security response-header middleware.

Sets headers that defend against common browser-side attacks:

- X-Content-Type-Options: nosniff — disables MIME sniffing
- X-Frame-Options: DENY — blocks framing (clickjacking)
- Referrer-Policy: same-origin — limits referrer leakage to other origins
- Strict-Transport-Security — pins HTTPS (only when served over TLS)
- Cross-Origin-Opener-Policy: same-origin — isolates browsing context
- Cross-Origin-Resource-Policy: same-origin — restricts cross-origin loads
- Content-Security-Policy — defense-in-depth against XSS

The CSP allows scripts only from the same origin (no remote CDNs, no
inline ``<script>`` blocks), forbids ``<object>``/``<embed>``/``<applet>``,
restricts ``<base>``, forbids framing entirely (in addition to the legacy
XFO header), and restricts form submission to the same origin. Inline
styles are permitted because Tailwind utilities compile to a same-origin
stylesheet but a few component templates rely on ``style=`` attributes.

``'unsafe-eval'`` is regrettably required for Alpine.js: the framework
compiles directives like ``x-data``, ``@click``, ``x-show`` via
``new Function()`` and silently breaks every interactive component
without it. This is documented behavior of Alpine v3 — a CSP-only build
exists but requires every directive to be rewritten as imported JS, an
order-of-magnitude refactor. The exposure ``'unsafe-eval'`` adds to
``script-src`` is bounded by the rest of the policy (only same-origin
scripts can call ``eval``-equivalents at all) and is the standard
trade-off accepted by every Alpine-based app.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


_CSP = "; ".join((
    "default-src 'self'",
    "script-src 'self' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
))


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": _CSP,
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
