"""Request body caps (group 3b, review of N-23).

Starlette bounds each form field (1 MB unless a route asks for more) and the
number of fields (1000), not a whole request: without a cap, an anonymous
POST to /login/submit could carry 1000 fields of 1 MB each. This middleware
gives every request a cap by its path. Starlette's RequestBodyLimitMiddleware
refuses a larger body with 413 Content Too Large while the body is read, or
before the response when its Content-Length already says so.
"""

import re
from collections.abc import Sequence

from starlette.middleware.body_limit import RequestBodyLimitMiddleware
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
        self._default = RequestBodyLimitMiddleware(app, default)
        self._by_path = [(re.compile(pattern), RequestBodyLimitMiddleware(app, limit))
                         for pattern, limit in by_path]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limited = next((capped for pattern, capped in self._by_path
                        if pattern.fullmatch(scope["path"])), self._default)
        await limited(scope, receive, send)
