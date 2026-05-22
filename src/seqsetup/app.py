"""Main FastHTML application."""

import hashlib
from pathlib import Path

from fasthtml.common import *

from starlette.responses import PlainTextResponse

from .csrf import OriginCheckMiddleware
from .data.instruments import set_instrument_definition_repo
from .middleware import make_auth_beforeware
from .repositories.base import ConflictError
from .routes import admin, api, api_tokens, auth, dashboard, export, indexes, local_users, main, profiles, runs, samples, swagger, validation, wizard
from .security_headers import SecurityHeadersMiddleware
from .services.log_capture import setup_log_capture
from .startup import (
    get_api_token_repo,
    get_app_context,
    get_instrument_definition_repo,
    init_auth_service,
    init_repos,
    init_scheduler,
    resolve_session_secret,
)

# Static files directory
static_dir = Path(__file__).parent / "static"

# Resolve session secret
SESSION_SECRET = resolve_session_secret()

# Initialize repositories
init_repos()

# Create auth middleware (needs api_token_repo for Bearer token verification)
bware = make_auth_beforeware(get_api_token_repo)

# Cache-busting hash for static assets
def _asset_hash(filename: str) -> str:
    path = static_dir / filename
    if path.exists():
        return hashlib.md5(path.read_bytes()).hexdigest()[:8]
    return "0"

_css_v = _asset_hash("css/app.css")
_js_v = _asset_hash("js/app.js")

# Create FastHTML app with session support.
# same_site="strict" defeats CSRF via cross-site form submissions (the audit's
# H3/M6 findings). sess_https_only is controlled by env so local-dev HTTP still
# works; production deployments must set SEQSETUP_HTTPS_ONLY=1.
import os as _os
_sess_https_only = _os.environ.get("SEQSETUP_HTTPS_ONLY", "").lower() in ("1", "true", "yes")


async def _conflict_handler(request, exc):
    """Translate a ConflictError into a 409 response with the user-facing message.

    The optimistic-locked save path on SequencingRun raises ConflictError when
    a concurrent edit has bumped the stored updated_at. Without this handler
    the response would be a 500 stack trace.
    """
    return PlainTextResponse(str(exc), status_code=409)


app, rt = fast_app(
    hdrs=[
        Link(rel="icon", type="image/svg+xml", href="/img/favicon.svg"),
        Link(rel="stylesheet", href=f"/css/app.css?v={_css_v}"),
        Script(src=f"/js/app.js?v={_js_v}"),
    ],
    pico=False,  # Use custom CSS instead of Pico
    secret_key=SESSION_SECRET,
    before=bware,
    static_path=str(static_dir),
    same_site="strict",
    sess_https_only=_sess_https_only,
    exception_handlers={ConflictError: _conflict_handler},
)

# Security response-header middleware (X-Content-Type-Options, X-Frame-Options,
# Referrer-Policy, Cross-Origin-* and HSTS-on-TLS). Applied to every response.
app.add_middleware(SecurityHeadersMiddleware)

# Origin/Host check on state-changing requests. Defense-in-depth alongside
# the session cookie's SameSite=Strict. See seqsetup.csrf for details and
# the SEQSETUP_TRUSTED_ORIGINS env var to allow additional origins.
app.add_middleware(OriginCheckMiddleware)

# Initialize services
set_instrument_definition_repo(get_instrument_definition_repo())  # Enable synced instruments
auth_service = init_auth_service()
init_scheduler()
setup_log_capture(["seqsetup"])

# Create shared AppContext for all routes
_ctx = get_app_context()

# Register routes
# Note: Order matters! More specific routes must come before generic patterns
api.register(app, rt, _ctx)
swagger.register(app, rt)
auth.register(app, rt, auth_service)
admin.register(app, rt, _ctx)
api_tokens.register(app, rt, _ctx)
local_users.register(app, rt, _ctx)
dashboard.register(app, rt, _ctx)
indexes.register(app, rt, _ctx)
profiles.register(app, rt, _ctx)
wizard.register(app, rt, _ctx)  # /runs/new/* before /runs/{run_id}
samples.register(app, rt, _ctx)
runs.register(app, rt, _ctx)
export.register(app, rt, _ctx)
validation.register(app, rt, _ctx)  # /runs/{run_id}/validation before /runs/{run_id}
main.register(app, rt, _ctx)  # /runs/{run_id} must be LAST


def main_func():
    """Entry point for running the application."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5001)


if __name__ == "__main__":
    main_func()
