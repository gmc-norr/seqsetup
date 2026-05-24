"""Playwright fixtures: boot the app in a thread, serve it on a free
port, hand a base_url to the tests.

We intentionally serve the REAL app (with the REAL templating + static
asset stack), not a TestClient transport, so the browser exercises the
exact pipeline a user hits. We DO patch in mongomock (same as the
integration ``fresh_app`` fixture) — without it, ``init_db()`` would
try to ping a real MongoDB on startup and fail in CI / dev machines
without a running server.
"""

import importlib
import os
import socket
import sys
import threading
import time
from contextlib import closing

import mongomock
import pytest
import uvicorn

from seqsetup.models.local_user import LocalUser
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.models.user import UserRole


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Session-scoped admin credentials used by the browser tests for login.
BROWSER_ADMIN = {"username": "browser-admin", "password": "Br0wser-Adm1n!"}


@pytest.fixture(scope="session")
def app_server(tmp_path_factory):
    """Boot seqsetup.app on a free port for the test session, backed by
    mongomock + a seeded admin user.
    """
    # --- Sandbox secrets / paths ---
    session_dir = tmp_path_factory.mktemp("browser-app")
    os.environ["SEQSETUP_SESSION_SECRET"] = "x" * 64
    os.environ["SEQSETUP_SESSKEY_PATH"] = str(session_dir / ".sesskey")

    # --- Patch init_db / get_db to use mongomock BEFORE app import ---
    # We can't use the integration fixture as-is (it's function-scoped
    # and uses monkeypatch); for the browser tests we patch the module
    # globals directly for the session.
    mongo_client = mongomock.MongoClient()
    db = mongo_client["seqsetup_test_browser"]

    from seqsetup.services import database as db_module
    db_module.init_db = lambda: db
    db_module.get_db = lambda: db
    db_module._db = db

    # Reset startup-module caches BEFORE app import.
    import seqsetup.startup as startup_module
    startup_module._db = None
    startup_module._repos = {}
    startup_module._github_sync_service = None
    startup_module._profile_sync_scheduler = None
    startup_module._auth_service = None

    # Also reset the data.instruments cache (same as integration conftest).
    from seqsetup.data import instruments as instruments_module
    instruments_module._synced_instruments_cache = None
    instruments_module._instrument_definition_repo = None

    # Reset log_capture handler (same reason).
    import logging
    from seqsetup.services import log_capture as log_capture_module
    if log_capture_module._log_capture_handler is not None:
        for name in ("seqsetup", ""):
            logging.getLogger(name).removeHandler(log_capture_module._log_capture_handler)
        log_capture_module._log_capture_handler = None

    # Now import the app — startup uses the patched db.
    if "seqsetup.app" in sys.modules:
        del sys.modules["seqsetup.app"]
    app_module = importlib.import_module("seqsetup.app")
    app = app_module.app
    ctx = app_module._ctx

    # Stop the background scheduler started during app import.
    scheduler = getattr(startup_module, "_profile_sync_scheduler", None)
    if scheduler is not None:
        try:
            scheduler.stop()
        except Exception:
            pass

    # --- Seed an admin user for login tests ---
    admin = LocalUser(
        username=BROWSER_ADMIN["username"],
        display_name="Browser Admin",
        email="browser@test.local",
        role=UserRole.ADMIN,
    )
    admin.set_password(BROWSER_ADMIN["password"])
    ctx.local_user_repo.save(admin)

    # --- Seed one DRAFT run so the dashboard tabs render. ---
    # The dashboard's empty-state branch (no runs) doesn't show tab
    # buttons; the HTMX swap test needs the tabs to exist so it can
    # click "Ready" and exercise the hx-get. One minimal draft is
    # enough — its content doesn't matter; only its presence does.
    seed_run = SequencingRun(
        run_name="Browser smoke seed run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=RunStatus.DRAFT,
        created_by=BROWSER_ADMIN["username"],
    )
    ctx.run_repo.save(seed_run)

    # --- Boot the server on a free port ---
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for the server to be ready.
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with closing(socket.create_connection(("127.0.0.1", port), timeout=0.5)):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("app server did not start within 10 seconds")

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def base_url(app_server):
    return app_server


@pytest.fixture
def admin_creds():
    """The seeded admin credentials — for tests that need to log in."""
    return BROWSER_ADMIN


@pytest.fixture
def logged_in_page(page, base_url, admin_creds):
    """A Playwright ``page`` that has already logged in as the seeded admin."""
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', admin_creds["username"])
    page.fill('input[name="password"]', admin_creds["password"])
    page.click('button[type="submit"]')
    # Wait for redirect to dashboard.
    page.wait_for_url(f"{base_url}/", timeout=5000)
    return page
