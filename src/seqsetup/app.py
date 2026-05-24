"""Main application module.

Single FastAPI host. HTML routes are registered as Starlette
``Route(...)`` objects appended to ``app.routes``; the ``/api/*``
surface is a FastAPI sub-app mounted at /api. FastAPI is used purely as
a Starlette-with-decorator-sugar host for the HTML side — the JSON API
uses its full Pydantic/OpenAPI toolkit.

FT components (``fasthtml.common``) remain as a templating DSL and are
rendered to HTML strings via the helpers in ``seqsetup.templating``.
They are progressively being ported to Jinja2 templates under
``templates/``; this is independent of the routing/middleware framework
choice.

Middleware order (outermost → innermost):
    SecurityHeadersMiddleware  ← response-header decorator
    OriginCheckMiddleware       ← CSRF defense-in-depth
    SessionMiddleware           ← parses/sets the session cookie
    AuthMiddleware              ← requires ``request.session`` to exist
"""

import os
from pathlib import Path

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
from starlette.staticfiles import StaticFiles

from .api.app import create_api_app
from .csrf import OriginCheckMiddleware
from .data.instruments import set_instrument_definition_repo
from .exception_handlers import install as install_exception_handlers
from .middleware import AuthMiddleware
from .routes import api_tokens, auth, dashboard, export, indexes, local_users, main, profiles, runs, samples, validation, wizard
from .routes.admin import (
    authentication as admin_authentication,
    config_sync as admin_config_sync,
    instruments as admin_instruments,
    logs as admin_logs,
    sample_api as admin_sample_api,
)
from .security_headers import SecurityHeadersMiddleware
from .services.log_capture import setup_log_capture
from .startup import (
    get_app_context,
    get_instrument_definition_repo,
    init_auth_service,
    init_repos,
    init_scheduler,
    resolve_session_secret,
)

# Static files directory
_STATIC_DIR = Path(__file__).parent / "static"

# Resolve session secret
_SESSION_SECRET = resolve_session_secret()

# Initialize repositories
init_repos()

# Production deployments must set SEQSETUP_HTTPS_ONLY=1 so the session cookie
# carries the Secure attribute. Local-dev HTTP leaves it unset.
_SESS_HTTPS_ONLY = os.environ.get("SEQSETUP_HTTPS_ONLY", "").lower() in ("1", "true", "yes")


# Disable FastAPI's built-in /docs, /redoc and /openapi.json at the root —
# the JSON API has its own same-origin Swagger UI at /api/docs (with a
# strict CSP) served by the mounted sub-app. A root-level Swagger would
# duplicate the surface and bypass the CSP.
app = FastAPI(
    title="SeqSetup",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Middleware ordering: Starlette's add_middleware prepends — the LAST
# add_middleware call ends up OUTERMOST. So the order below produces the
# wrap order documented in the module docstring (Security → Origin →
# Session → Auth → app).
app.add_middleware(AuthMiddleware)
# Cookie name is Starlette's default ``session`` (was ``session_`` under the
# previous FastHTML host). Sessions from the old host can't be read by the
# new host and vice-versa — operators upgrading from a FastHTML deployment
# should expect every user to be silently logged out once.
app.add_middleware(
    SessionMiddleware,
    secret_key=_SESSION_SECRET,
    same_site="strict",
    https_only=_SESS_HTTPS_ONLY,
)
app.add_middleware(OriginCheckMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Register HTML-aware exception handlers (HTTPException, RequestValidationError,
# ConflictError). Must be registered AFTER middleware and BEFORE the /api sub-app
# mount so that the sub-app can keep its own JSON-default handlers.
install_exception_handlers(app)

# Static asset mounts. The previous FastHTML host auto-mounted these by
# scanning the static dir; FastAPI/Starlette needs each subdir mounted
# explicitly. Template references (/css/app.css, /js/app.js,
# /img/favicon.svg) are unchanged.
app.mount("/css", StaticFiles(directory=str(_STATIC_DIR / "css")), name="css")
app.mount("/js", StaticFiles(directory=str(_STATIC_DIR / "js")), name="js")
app.mount("/img", StaticFiles(directory=str(_STATIC_DIR / "img")), name="img")
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# Browsers default to /favicon.ico but the real icon is /img/favicon.svg.
# Redirect rather than 404 — silences noisy access logs on every page load.
@app.get("/favicon.ico", include_in_schema=False)
def _favicon_redirect():
    return RedirectResponse("/img/favicon.svg", status_code=301)

# Initialize services
set_instrument_definition_repo(get_instrument_definition_repo())  # Enable synced instruments
auth_service = init_auth_service()
init_scheduler()
setup_log_capture(["seqsetup"])

# Create shared AppContext for all routes
_ctx = get_app_context()

# Mount the FastAPI sub-app for /api/* — auto-generated OpenAPI at
# /api/openapi.json and same-origin Swagger UI at /api/docs.
# Mount BEFORE the HTML route registrations so /api/* path matching wins.
_api_subapp = create_api_app(_ctx)
app.mount("/api", _api_subapp)

# HTML route registration. Order matters because Starlette matches in
# registration order and several paths share prefixes:
#   - Specific paths before generic patterns
#   - /runs/new/* before /runs/{run_id}
#   - /runs/{run_id}/validation, /runs/{run_id}/samples/... before /runs/{run_id}
#   - /runs/{run_id} (edit page) registered LAST
app.include_router(auth.make_router(auth_service))
app.include_router(admin_authentication.router)
app.include_router(admin_config_sync.router)
app.include_router(admin_instruments.router)
app.include_router(admin_logs.router)
app.include_router(admin_sample_api.router)
app.include_router(api_tokens.router)
app.include_router(local_users.router)
app.include_router(dashboard.router)
app.include_router(indexes.router)
app.include_router(profiles.router)
wizard.register(app, _ctx)
samples.register(app, _ctx)
runs.register(app, _ctx)
export.register(app, _ctx)
validation.register(app, _ctx)
main.register(app, _ctx)


def main_func():
    """Entry point for running the application."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5001)


if __name__ == "__main__":
    main_func()
