"""Security response-header middleware.

Sets headers that defend against common browser-side attacks:

- X-Content-Type-Options: nosniff — disables MIME sniffing
- X-Frame-Options: DENY — blocks framing (clickjacking)
- Referrer-Policy: same-origin — limits referrer leakage to other origins
- Strict-Transport-Security — pins HTTPS (when served over TLS, and on every
  answer when SEQSETUP_HTTPS_ONLY is on)
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

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response


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


_HTTPS_ONLY_ON = ("1", "true", "yes")
_HTTPS_ONLY_OFF = ("", "0", "false", "no")


def https_only_from_env() -> bool:
    """SEQSETUP_HTTPS_ONLY as a bool. Raise RuntimeError on a value it does not know.

    Read loosely, a typo such as ``on`` would quietly leave the session cookie
    without Secure, so a value outside the two lists stops the start.
    """
    value = os.environ.get("SEQSETUP_HTTPS_ONLY", "")
    if value.lower() in _HTTPS_ONLY_ON:
        return True
    if value.lower() in _HTTPS_ONLY_OFF:
        return False
    raise RuntimeError(
        f"SEQSETUP_HTTPS_ONLY={value!r} is not a known value. Set it to 1 (or true, yes) "
        "when users reach SeqSetup over HTTPS, or to 0 (or false, no) when they do not."
    )


def apply_security_headers(response: Response, is_https: bool) -> None:
    """Set security headers on the given response in-place.

    Strict-Transport-Security is set only when ``is_https``: the request came
    over HTTPS, or SEQSETUP_HTTPS_ONLY is on. Browsers ignore HSTS that arrives
    over plain HTTP (RFC 6797, section 8.1); unset, a developer's plain-HTTP
    machine gets none.
    """
    for name, value in _SECURITY_HEADERS.items():
        # Don't clobber a value an inner handler already set deliberately.
        response.headers.setdefault(name, value)
    if is_https:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Starlette ASGI middleware that applies the security headers above.

    With ``https_only`` (SEQSETUP_HTTPS_ONLY) every answer gets HSTS, also when
    a TLS proxy the app does not trust makes the request look like http.
    """

    def __init__(self, app, https_only: bool = False):
        super().__init__(app)
        self._https_only = https_only

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # The scope's scheme, not request.url: a Host header such as "[" makes
        # request.url raise, and the answer would leave without these headers.
        apply_security_headers(
            response, is_https=self._https_only or request.scope.get("scheme") == "https"
        )
        return response


def server_error_handler(https_only: bool):
    """A handler for unhandled errors: today's 500 page, with the security headers.

    Starlette makes an unhandled error's 500 in its outermost layer, outside
    every middleware, so SecurityHeadersMiddleware never sees it. Starlette
    still re-raises the error after this answer, so the server logs it.
    """

    async def handle(request: Request, exc: Exception) -> Response:
        response = PlainTextResponse("Internal Server Error", status_code=500)
        apply_security_headers(
            response, is_https=https_only or request.scope.get("scheme") == "https"
        )
        return response

    return handle
