"""Integration-test fixtures.

Boots a fresh FastHTML app instance per test with:
  - mongomock-backed MongoDB (no real mongod required)
  - Isolated session secret + sesskey (per-test tmp dir)
  - Pre-seeded admin user for authenticated flows

The app is bootstrapped via ``importlib.reload(seqsetup.app)`` after the
patches are in place. This keeps the production import-time wiring as the
canonical source of truth — tests don't duplicate the route registration
list, so adding a new route doesn't silently bypass smoke coverage.
"""

import importlib
import re
import sys
from pathlib import Path

import mongomock
import pytest
from starlette.testclient import TestClient

from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import UserRole


@pytest.fixture(autouse=True)
def _clear_validation_cache():
    """Ensure each test starts with a fresh validation cache."""
    from seqsetup.services.validation import clear_validation_cache
    clear_validation_cache()
    yield
    clear_validation_cache()


@pytest.fixture
def isolated_mongo(monkeypatch):
    """A fresh mongomock database per test."""
    client = mongomock.MongoClient()
    db = client["seqsetup_test"]

    # Replace init_db / get_db with the fake.
    from seqsetup.services import database as db_module
    monkeypatch.setattr(db_module, "init_db", lambda: db)
    monkeypatch.setattr(db_module, "get_db", lambda: db)
    monkeypatch.setattr(db_module, "_db", db)
    # startup.py imports init_db by name, so patch it there too. Otherwise a
    # file run on its own keeps the first test's database for every test.
    import seqsetup.startup as startup_module
    monkeypatch.setattr(startup_module, "init_db", lambda: db)

    yield db


@pytest.fixture
def fresh_app(isolated_mongo, monkeypatch, tmp_path):
    """Reload seqsetup.app against the isolated mongo + isolated session secret.

    Returns (app, ctx, mongo_db) — tests can mutate ctx repos directly to set
    up state, then exercise endpoints via TestClient on app.
    """
    # Sandbox the session secret to a per-test tmpfile to avoid touching
    # the real .sesskey, and prevent SecretHandler races between tests.
    monkeypatch.setenv("SEQSETUP_SESSION_SECRET", "x" * 64)
    # CSRF middleware reads this at construction; clear to default behavior.
    monkeypatch.delenv("SEQSETUP_TRUSTED_ORIGINS", raising=False)

    # Sandbox the sesskey file path too, in case the env var is absent.
    monkeypatch.setattr(
        "seqsetup.startup.SESSKEY_PATH",
        tmp_path / ".sesskey",
    )

    # Reset module-level state on the startup module (cached repos/services)
    # so reload sees fresh state. Stop the previous scheduler BEFORE nulling
    # the reference — otherwise the daemon thread keeps ticking against a
    # dead config repo for the rest of the test run.
    import seqsetup.startup as startup_module
    prev_scheduler = getattr(startup_module, "_profile_sync_scheduler", None)
    if prev_scheduler is not None:
        try:
            prev_scheduler.stop()
        except Exception:
            pass
    startup_module._db = None
    startup_module._repos = {}
    startup_module._github_sync_service = None
    startup_module._profile_sync_scheduler = None
    startup_module._auth_service = None

    # The data.instruments synced cache uses module-level state too.
    from seqsetup.data import instruments as instruments_module
    instruments_module._synced_instruments_cache = None
    instruments_module._instrument_definition_repo = None

    # The log_capture handler accumulates duplicate registrations on each
    # reload because setup_log_capture(..) calls logger.addHandler without
    # checking for duplicates. Drop any prior handler from the seqsetup
    # logger before the reload re-adds one.
    import logging
    from seqsetup.services import log_capture as log_capture_module
    if log_capture_module._log_capture_handler is not None:
        for name in ("seqsetup", ""):  # both per-logger and root
            logger = logging.getLogger(name)
            try:
                logger.removeHandler(log_capture_module._log_capture_handler)
            except Exception:
                pass
        log_capture_module._log_capture_handler = None

    # Reset rate-limit counters so a previous test's traffic doesn't bleed
    # into this one. Without this, tests that do many requests trip 429.
    from seqsetup.rate_limit import reset_all_limiters
    reset_all_limiters()

    # Clear the validation memoization cache so a previous test's run
    # (potentially sharing the same run.id) can't leak stale results.
    from seqsetup.services.validation import clear_validation_cache
    clear_validation_cache()

    # Reload the app module to re-run the bootstrap wiring against mongomock.
    if "seqsetup.app" in sys.modules:
        del sys.modules["seqsetup.app"]
    app_module = importlib.import_module("seqsetup.app")

    # Don't keep the background scheduler running in tests.
    scheduler = getattr(startup_module, "_profile_sync_scheduler", None)
    if scheduler is not None:
        try:
            scheduler.stop()
        except Exception:
            pass

    yield app_module.app, app_module._ctx, isolated_mongo

    # The app set the audit sink (module state) to this test's database; don't
    # let later tests keep writing audit events into it.
    from seqsetup.services.audit_log import set_audit_sink
    set_audit_sink(None)


def disable_repos(ctx, *repo_keys: str) -> None:
    """Null out repos on BOTH the test's ctx AND startup._repos.

    Routes migrated to Depends(get_ctx) read from startup._repos
    per-request — mutating only ctx.<repo> = None has no effect on
    those routes. This helper does both mutations atomically.

    Repo key examples: "test_profile", "app_profile", "run",
    "index_kit", "local_user", "auth_config", "sample_api_config".
    Mirrors the keys in startup._REPO_REGISTRY.
    """
    from seqsetup import startup
    for key in repo_keys:
        # Set the attribute name on the ctx (key + "_repo" — the convention)
        setattr(ctx, f"{key}_repo", None)
        # And null the startup module-level entry so get_app_context()
        # rebuilds AppContext without the repo too.
        if key in startup._repos:
            startup._repos[key] = None


@pytest.fixture
def admin_user_seeded(fresh_app):
    """Insert a known-good admin into the LocalUser repo and return creds."""
    _app, ctx, _db = fresh_app
    user = LocalUser(
        username="admin-test",
        display_name="Test Admin",
        email="admin@test.local",
        role=UserRole.ADMIN,
    )
    user.set_password("Cl1nical-Admin!")
    ctx.local_user_repo.save(user)
    return {"username": "admin-test", "password": "Cl1nical-Admin!"}


@pytest.fixture
def standard_user_seeded(fresh_app):
    """Insert a standard user and return creds."""
    _app, ctx, _db = fresh_app
    user = LocalUser(
        username="operator",
        display_name="Test Operator",
        email="op@test.local",
        role=UserRole.STANDARD,
    )
    user.set_password("Strong-Op3r4tor!")
    ctx.local_user_repo.save(user)
    return {"username": "operator", "password": "Strong-Op3r4tor!"}


@pytest.fixture
def client(fresh_app):
    """A Starlette TestClient pointed at the fresh app.

    Sends Origin=http://testserver by default so the CSRF middleware accepts
    same-origin POSTs. Tests that exercise the CSRF rejection path can pass
    an explicit ``headers={'Origin': 'http://attacker'}``.
    """
    app, _ctx, _db = fresh_app
    return TestClient(app, base_url="http://testserver")


@pytest.fixture
def logged_in_client(fresh_app, admin_user_seeded):
    """Test client with an authenticated admin session.

    POSTs to /login/submit, then returns the client with the session cookie set.
    """
    app, _ctx, _db = fresh_app
    c = TestClient(app, base_url="http://testserver")
    response = c.post(
        "/login/submit",
        data={
            "username": admin_user_seeded["username"],
            "password": admin_user_seeded["password"],
        },
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    # Login should 303 to /
    assert response.status_code == 303, (
        f"Login failed (status={response.status_code}); body={response.text[:300]}"
    )
    return c


@pytest.fixture
def logged_in_standard_client(fresh_app, standard_user_seeded):
    """A TestClient logged in as a non-admin standard user.

    Use this fixture to verify admin routes return 403 to non-admins,
    or that role-gated branches behave correctly for the standard role.
    """
    app, _ctx, _db = fresh_app
    c = TestClient(app, base_url="http://testserver")
    response = c.post(
        "/login/submit",
        data={
            "username": standard_user_seeded["username"],
            "password": standard_user_seeded["password"],
        },
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    # Login should 303 to /
    assert response.status_code == 303, (
        f"Standard-user login failed (status={response.status_code}); body={response.text[:300]}"
    )
    return c


def mark_ready(client, run_id: str, headers: dict):
    """POST Mark Ready; if the color-balance question comes back, answer it
    the way its form does. Returns the last response. For tests about
    something else that happen to use a one-sample two-color run."""
    resp = client.post(f"/runs/{run_id}/status/ready", headers=headers)
    if "Mark Ready anyway" not in resp.text:
        return resp
    fields = dict(re.findall(r'name="(color_balance_[a-z_]+)" value="([^"]*)"', resp.text))
    answered = client.post(f"/runs/{run_id}/status/ready", data=fields, headers=headers)
    # Re-asking is also a 200, so a caller that only checks the status code
    # would pass on a run that stayed Draft. Fail here instead.
    assert "Mark Ready anyway" not in answered.text, (
        "the color-balance answer was not accepted; the question came back"
    )
    return answered
