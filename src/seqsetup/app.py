"""Main FastHTML application."""

from pathlib import Path

from fasthtml.common import *

from .data.instruments import set_instrument_definition_repo
from .middleware import make_auth_beforeware
from .routes import admin, api, api_tokens, auth, dashboard, export, indexes, local_users, main, profiles, runs, samples, swagger, validation, wizard
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

# Create FastHTML app with session support
app, rt = fast_app(
    hdrs=[
        Link(rel="icon", type="image/svg+xml", href="/img/favicon.svg"),
        Link(rel="stylesheet", href="/css/app.css"),
        Script(src="/js/app.js"),
    ],
    pico=False,  # Use custom CSS instead of Pico
    secret_key=SESSION_SECRET,
    before=bware,
    static_path=str(static_dir),
)

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
