"""Request body caps (group 3b, review of N-23).

Starlette bounds each form field (1 MB unless a route asks for more) and the
number of fields (1000), not a whole request: without a cap, an anonymous
POST to /login/submit could carry 1000 fields of 1 MB each. This middleware
gives every request a cap by its path. A body whose Content-Length is over
the cap is refused with 413 before any route runs, so a 413 means nothing
happened; a body sent without a Content-Length is counted while it is read,
by Starlette's RequestBodyLimitMiddleware, which refuses it with 413 too.
"""

import re
from collections.abc import Sequence

from starlette.datastructures import Headers
from starlette.middleware.body_limit import RequestBodyLimitMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send

DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024


class BodyLimitMiddleware:
    """Cap each request body. The first pattern that matches the whole path
    gives the cap; any other path gets ``default``."""

    def __init__(
        self,
        app: ASGIApp,
        default: int = DEFAULT_MAX_BODY_BYTES,
        by_path: Sequence[tuple[str, int]] = (),
    ) -> None:
        self.app = app
        self._default = (default, RequestBodyLimitMiddleware(app, default))
        self._by_path = [(re.compile(pattern), (limit, RequestBodyLimitMiddleware(app, limit)))
                         for pattern, limit in by_path]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit, limited = next((capped for pattern, capped in self._by_path
                               if pattern.fullmatch(scope["path"])), self._default)
        # Starlette's cap acts only when the body is read or the response
        # starts: a route that never reads its body would run, and save,
        # before its answer became 413.
        length = Headers(scope=scope).get("content-length", "")
        if length.isdigit() and int(length) > limit:
            response = PlainTextResponse(
                f"Content Too Large (max {limit // (1024 * 1024)} MB)", status_code=413)
            await response(scope, receive, send)
            return
        await limited(scope, receive, send)
