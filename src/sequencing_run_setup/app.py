"""Main FastHTML application."""

import secrets
from pathlib import Path

from fasthtml.common import *
from starlette.responses import RedirectResponse, Response

from .models.user import User
from .repositories import IndexKitRepository, RunRepository, TestRepository
from .repositories.auth_config_repo import AuthConfigRepository
from .repositories.instrument_config_repo import InstrumentConfigRepository
from .repositories.application_profile_repo import ApplicationProfileRepository
from .repositories.test_profile_repo import TestProfileRepository
from .repositories.profile_sync_config_repo import ProfileSyncConfigRepository
from .repositories.api_token_repo import ApiTokenRepository
from .repositories.local_user_repo import LocalUserRepository
from .repositories.sample_api_config_repo import SampleApiConfigRepository
from .routes import admin, api, api_tokens, auth, dashboard, export, indexes, local_users, main, profiles, runs, samples, validation, wizard
from .services.auth import AuthService
from .services.database import get_db, init_db
from .services.github_sync import GitHubSyncService
from .services.scheduler import ProfileSyncScheduler

# Configuration paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "users.yaml"
SESSKEY_PATH = PROJECT_ROOT / ".sesskey"

# Session secret key
if SESSKEY_PATH.exists():
    SESSION_SECRET = SESSKEY_PATH.read_text().strip()
else:
    SESSION_SECRET = secrets.token_hex(32)
    SESSKEY_PATH.write_text(SESSION_SECRET)

# Auth service (get_auth_config is set after function is defined)
auth_service = None


def init_auth_service():
    """Initialize auth service with config."""
    global auth_service
    auth_service = AuthService(CONFIG_PATH, get_auth_config, get_local_user_repo)

# Routes that don't require authentication
PUBLIC_ROUTES = {"/login", "/login/submit", "/favicon.ico"}


# Initialize MongoDB and repositories
_db = None
_repos = {}

# Services
_github_sync_service = None
_profile_sync_scheduler = None

# Repository class registry: maps getter name to (class, key)
_REPO_REGISTRY = {
    "index_kit": IndexKitRepository,
    "run": RunRepository,
    "test": TestRepository,
    "auth_config": AuthConfigRepository,
    "instrument_config": InstrumentConfigRepository,
    "app_profile": ApplicationProfileRepository,
    "test_profile": TestProfileRepository,
    "profile_sync_config": ProfileSyncConfigRepository,
    "api_token": ApiTokenRepository,
    "local_user": LocalUserRepository,
    "sample_api_config": SampleApiConfigRepository,
}


def init_repos():
    """Initialize database and repositories."""
    global _db
    _db = init_db()
    for key, repo_class in _REPO_REGISTRY.items():
        _repos[key] = repo_class(_db)


def _get_repo(key: str):
    """Get a repository by key, initializing if needed."""
    if key not in _repos:
        init_repos()
    return _repos[key]


def get_index_kit_repo() -> IndexKitRepository:
    return _get_repo("index_kit")

def get_run_repo() -> RunRepository:
    return _get_repo("run")

def get_test_repo() -> TestRepository:
    return _get_repo("test")

def get_auth_config_repo() -> AuthConfigRepository:
    return _get_repo("auth_config")

def get_instrument_config_repo() -> InstrumentConfigRepository:
    return _get_repo("instrument_config")

def get_auth_config():
    """Get the current auth configuration (for auth service)."""
    return get_auth_config_repo().get()

def get_app_profile_repo() -> ApplicationProfileRepository:
    return _get_repo("app_profile")

def get_test_profile_repo() -> TestProfileRepository:
    return _get_repo("test_profile")

def get_profile_sync_config_repo() -> ProfileSyncConfigRepository:
    return _get_repo("profile_sync_config")

def get_api_token_repo() -> ApiTokenRepository:
    return _get_repo("api_token")

def get_local_user_repo() -> LocalUserRepository:
    return _get_repo("local_user")

def get_sample_api_config_repo() -> SampleApiConfigRepository:
    return _get_repo("sample_api_config")


def get_github_sync_service() -> GitHubSyncService:
    """Get the GitHub sync service."""
    global _github_sync_service
    if _github_sync_service is None:
        _github_sync_service = GitHubSyncService(
            get_profile_sync_config_repo(),
            get_app_profile_repo(),
            get_test_profile_repo(),
        )
    return _github_sync_service


def init_scheduler():
    """Initialize and start the profile sync scheduler."""
    global _profile_sync_scheduler
    _profile_sync_scheduler = ProfileSyncScheduler(
        get_github_sync_service(),
        get_profile_sync_config_repo(),
    )
    _profile_sync_scheduler.start()


def get_repos():
    """Get all repositories as a tuple."""
    return get_index_kit_repo(), get_run_repo(), get_test_repo()

# Static files directory
static_dir = Path(__file__).parent / "static"


def auth_beforeware(req, sess):
    """
    Beforeware to check authentication on protected routes.

    Adds `auth` attribute to request scope with User object or None.
    Redirects to login if not authenticated on protected routes.
    """
    path = req.url.path

    # Check if route is public
    if path in PUBLIC_ROUTES or path.startswith(("/static", "/css", "/js", "/img")):
        req.scope["auth"] = None
        return

    # API routes require Bearer token authentication
    if path.startswith("/api/"):
        auth_header = req.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token_str = auth_header[7:]
            api_token = get_api_token_repo().verify_token(token_str)
            if api_token:
                req.scope["auth"] = None
                req.scope["api_token"] = api_token
                return
        return Response("Unauthorized", status_code=401)

    # Check session for authenticated user
    user_data = sess.get("user")
    if not user_data:
        return RedirectResponse("/login", status_code=303)

    # Restore User object from session
    try:
        user = User.from_dict(user_data)
        req.scope["auth"] = user
    except (KeyError, ValueError):
        # Invalid session data, clear and redirect
        sess.clear()
        return RedirectResponse("/login", status_code=303)


# Create Beforeware
bware = Beforeware(auth_beforeware, skip=[r"/favicon\.ico", r"/static/.*"])

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

# Initialize repositories and auth service on startup
init_repos()
init_auth_service()
init_scheduler()

# Register routes
# Note: Order matters! More specific routes must come before generic patterns
api.register(app, rt, get_run_repo)
auth.register(app, rt, auth_service)
admin.register(
    app, rt,
    get_auth_config_repo,
    get_instrument_config_repo,
    get_profile_sync_config_repo,
    get_github_sync_service,
    get_app_profile_repo,
    get_test_profile_repo,
    get_sample_api_config_repo,
)
api_tokens.register(app, rt, get_api_token_repo)
local_users.register(app, rt, get_local_user_repo)
dashboard.register(app, rt, get_run_repo)
indexes.register(app, rt, get_index_kit_repo)
profiles.register(app, rt, get_test_profile_repo, get_app_profile_repo)
wizard.register(app, rt, get_run_repo, get_index_kit_repo, get_test_repo, get_sample_api_config_repo)  # /runs/new/* before /runs/{run_id}
samples.register(app, rt, get_run_repo, get_index_kit_repo, get_sample_api_config_repo)
runs.register(app, rt, get_run_repo, get_test_profile_repo, get_app_profile_repo, get_instrument_config_repo)
export.register(app, rt, get_run_repo, get_index_kit_repo, get_test_profile_repo, get_app_profile_repo, get_instrument_config_repo)
validation.register(app, rt, get_run_repo, get_test_profile_repo, get_app_profile_repo, get_instrument_config_repo)  # /runs/{run_id}/validation before /runs/{run_id}
main.register(app, rt, get_run_repo, get_index_kit_repo)  # /runs/{run_id} must be LAST



def main_func():
    """Entry point for running the application."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5001)


if __name__ == "__main__":
    main_func()
