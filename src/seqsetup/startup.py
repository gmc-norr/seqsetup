"""Application startup: configuration, repository initialization, and service factories."""

import os
import secrets
from pathlib import Path

from .context import AppContext
from .repositories import IndexKitRepository, RunRepository, TestRepository
from .repositories.auth_config_repo import AuthConfigRepository
from .repositories.instrument_config_repo import InstrumentConfigRepository
from .repositories.application_profile_repo import ApplicationProfileRepository
from .repositories.test_profile_repo import TestProfileRepository
from .repositories.profile_sync_config_repo import ProfileSyncConfigRepository
from .repositories.api_token_repo import ApiTokenRepository
from .repositories.local_user_repo import LocalUserRepository
from .repositories.sample_api_config_repo import SampleApiConfigRepository
from .repositories.instrument_definition_repo import InstrumentDefinitionRepository
from .services.auth import AuthService
from .services.database import init_db
from .services.github_sync import GitHubSyncService
from .services.scheduler import ProfileSyncScheduler

# Configuration paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "users.yaml"
SESSKEY_PATH = PROJECT_ROOT / ".sesskey"


def resolve_session_secret() -> str:
    """Resolve session secret from environment or file.

    Priority: SEQSETUP_SESSION_SECRET env var > .sesskey file > auto-generate.
    """
    secret = os.environ.get("SEQSETUP_SESSION_SECRET")
    if secret:
        return secret
    if SESSKEY_PATH.exists():
        return SESSKEY_PATH.read_text().strip()
    secret = secrets.token_hex(32)
    SESSKEY_PATH.write_text(secret)
    return secret


# Repository class registry: maps key to class
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
    "instrument_definition": InstrumentDefinitionRepository,
}

# Module-level state
_db = None
_repos = {}
_github_sync_service = None
_profile_sync_scheduler = None
_auth_service = None


def init_repos():
    """Initialize database and all repositories."""
    global _db
    _db = init_db()
    for key, repo_class in _REPO_REGISTRY.items():
        _repos[key] = repo_class(_db)


def _get_repo(key: str):
    """Get a repository by key, initializing if needed."""
    if key not in _repos:
        init_repos()
    return _repos[key]


# Typed getter functions for each repository

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

def get_instrument_definition_repo() -> InstrumentDefinitionRepository:
    return _get_repo("instrument_definition")


def get_app_context() -> AppContext:
    """Create an AppContext with all repositories and service factories."""
    return AppContext(
        run_repo=get_run_repo(),
        index_kit_repo=get_index_kit_repo(),
        test_repo=get_test_repo(),
        test_profile_repo=get_test_profile_repo(),
        app_profile_repo=get_app_profile_repo(),
        instrument_config_repo=get_instrument_config_repo(),
        auth_config_repo=get_auth_config_repo(),
        sample_api_config_repo=get_sample_api_config_repo(),
        api_token_repo=get_api_token_repo(),
        local_user_repo=get_local_user_repo(),
        instrument_definition_repo=get_instrument_definition_repo(),
        profile_sync_config_repo=get_profile_sync_config_repo(),
        get_github_sync_service=get_github_sync_service,
    )


def init_auth_service() -> AuthService:
    """Initialize and return the auth service."""
    global _auth_service
    _auth_service = AuthService(CONFIG_PATH, get_auth_config, get_local_user_repo)
    return _auth_service


def get_github_sync_service() -> GitHubSyncService:
    """Get or create the GitHub sync service (lazy singleton)."""
    global _github_sync_service
    if _github_sync_service is None:
        _github_sync_service = GitHubSyncService(
            get_profile_sync_config_repo(),
            get_app_profile_repo(),
            get_test_profile_repo(),
            get_instrument_definition_repo(),
            get_index_kit_repo(),
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
