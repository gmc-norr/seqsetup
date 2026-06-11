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
import itertools
import os
import socket
import sys
import threading
import time
from contextlib import closing
from datetime import datetime

import mongomock
import pytest
import uvicorn

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.local_user import LocalUser
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.models.test_profile import TestProfile
from seqsetup.models.user import UserRole

# Module-level AppContext reference, set once by app_server and used by
# function-scoped fixtures that need direct repo access (e.g. mutable_run_id).
_app_ctx = None
_mutable_run_counter = itertools.count(1)

# Fixed IDs used by screenshot/a11y tests for stable, deterministic URLs.
DRAFT_RUN_ID = "screenshot-draft-run"
SCREENSHOT_DRAFT_RUN_ID = "screenshot-oracle-run"  # dedicated to the screenshot oracle — never mutated by other tests
COLLISION_RUN_ID = "screenshot-collision-run"
READY_RUN_ID = "screenshot-ready-run"
ARCHIVED_RUN_ID = "screenshot-archived-run"
SCREENSHOT_KIT_NAME = "Screenshot-TestKit"


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
    # Raise the login rate limit so the full browser-test suite can log in
    # once per test function without hitting the production-default 20/60 s cap.
    os.environ.setdefault("SEQSETUP_LOGIN_RATE_LIMIT", "100")

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

    # Expose the AppContext to function-scoped fixtures.
    global _app_ctx
    _app_ctx = ctx

    # Stop the background scheduler started during app import.
    scheduler = getattr(startup_module, "_profile_sync_scheduler", None)
    if scheduler is not None:
        try:
            scheduler.stop()
        except Exception:
            pass

    # --- Seed an admin user for login tests ---
    _t_admin = datetime(2026, 1, 10, 7, 0, 0)
    admin = LocalUser(
        username=BROWSER_ADMIN["username"],
        display_name="Browser Admin",
        email="browser@test.local",
        role=UserRole.ADMIN,
        created_at=_t_admin,
        updated_at=_t_admin,
    )
    admin.set_password(BROWSER_ADMIN["password"])
    # set_password() bumps updated_at to datetime.now(); pin it back to the
    # fixed value so admin-users.html renders a deterministic timestamp.
    admin.updated_at = _t_admin
    ctx.local_user_repo.save(admin)

    # --- Seed one DRAFT run so the dashboard tabs render. ---
    # The dashboard's empty-state branch (no runs) doesn't show tab
    # buttons; the HTMX swap test needs the tabs to exist so it can
    # click "Ready" and exercise the hx-get. One minimal draft is
    # enough — its content doesn't matter; only its presence does.
    _t_seed = datetime(2026, 1, 10, 8, 0, 0)
    seed_run = SequencingRun(
        run_name="Browser smoke seed run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=RunStatus.DRAFT,
        created_by=BROWSER_ADMIN["username"],
        created_at=_t_seed,
        updated_at=_t_seed,
    )
    ctx.run_repo.save(seed_run)

    # --- Seed a standard PAIR index kit so the index panel populates. ---
    screenshot_kit = IndexKit(
        name=SCREENSHOT_KIT_NAME,
        version="1.0",
        description="Standard dual-index kit for screenshot tests",
        index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[
            IndexPair(
                id="sck-p1", name="UDP0001",
                index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
                index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5),
                well_position="A01",
            ),
            IndexPair(
                id="sck-p2", name="UDP0002",
                index1=Index(name="i7-02", sequence="TCCGGAGA", index_type=IndexType.I7),
                index2=Index(name="i5-02", sequence="ATAGAGGC", index_type=IndexType.I5),
                well_position="B01",
            ),
            IndexPair(
                id="sck-p3", name="UDP0003",
                index1=Index(name="i7-03", sequence="CGCTCATT", index_type=IndexType.I7),
                index2=Index(name="i5-03", sequence="CCTATCCT", index_type=IndexType.I5),
                well_position="C01",
            ),
            IndexPair(
                id="sck-p4", name="UDP0004",
                index1=Index(name="i7-04", sequence="GAGATTCC", index_type=IndexType.I7),
                index2=Index(name="i5-04", sequence="GGCTCTGA", index_type=IndexType.I5),
                well_position="D01",
            ),
        ],
        created_by=BROWSER_ADMIN["username"],
    )
    ctx.index_kit_repo.save(screenshot_kit)

    # --- Seed one test profile so the run-editor test-id dropdown is non-empty. ---
    screenshot_profile = TestProfile(
        id="screenshot-wgs-profile",
        test_type="WGS",
        test_name="Whole Genome Sequencing",
        description="WGS test profile for screenshot tests",
        version="1.0.0",
        synced_at=datetime(2026, 1, 10, 7, 0, 0),
    )
    ctx.test_profile_repo.save(screenshot_profile)

    # --- Seed a representative DRAFT run with ~6 samples (some indexed, some not). ---
    _t_draft = datetime(2026, 1, 10, 9, 0, 0)
    draft_run = SequencingRun(
        id=DRAFT_RUN_ID,
        run_name="Screenshot draft run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=RunStatus.DRAFT,
        created_by=BROWSER_ADMIN["username"],
        updated_by=BROWSER_ADMIN["username"],
        created_at=_t_draft,
        updated_at=_t_draft,
    )
    # 3 indexed samples
    draft_run.add_sample(Sample(
        id="ss-draft-s1", sample_id="SAMPLE-01", sample_name="Sample One",
        index_pair=IndexPair(
            id="sck-p1", name="UDP0001",
            index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    draft_run.add_sample(Sample(
        id="ss-draft-s2", sample_id="SAMPLE-02", sample_name="Sample Two",
        index_pair=IndexPair(
            id="sck-p2", name="UDP0002",
            index1=Index(name="i7-02", sequence="TCCGGAGA", index_type=IndexType.I7),
            index2=Index(name="i5-02", sequence="ATAGAGGC", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    draft_run.add_sample(Sample(
        id="ss-draft-s3", sample_id="SAMPLE-03", sample_name="Sample Three",
        index_pair=IndexPair(
            id="sck-p3", name="UDP0003",
            index1=Index(name="i7-03", sequence="CGCTCATT", index_type=IndexType.I7),
            index2=Index(name="i5-03", sequence="CCTATCCT", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    # 3 unindexed samples
    draft_run.add_sample(Sample(
        id="ss-draft-s4", sample_id="SAMPLE-04", sample_name="Sample Four",
        lanes=[1],
    ))
    draft_run.add_sample(Sample(
        id="ss-draft-s5", sample_id="SAMPLE-05", sample_name="Sample Five",
        lanes=[1],
    ))
    draft_run.add_sample(Sample(
        id="ss-draft-s6", sample_id="SAMPLE-06", sample_name="Sample Six",
        lanes=[1],
    ))
    ctx.run_repo.save(draft_run)

    # --- Seed a dedicated DRAFT run for the screenshot oracle (never mutated by other tests). ---
    # Visually equivalent to draft_run: 3 indexed + 3 unindexed samples, same kit.
    # Kept separate so mutation tests (keyboard-assign, drag-drop) can use draft_run freely.
    _t_oracle = datetime(2026, 1, 10, 9, 30, 0)
    oracle_run = SequencingRun(
        id=SCREENSHOT_DRAFT_RUN_ID,
        run_name="Screenshot draft run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=RunStatus.DRAFT,
        created_by=BROWSER_ADMIN["username"],
        updated_by=BROWSER_ADMIN["username"],
        created_at=_t_draft,
        updated_at=_t_draft,
    )
    # 3 indexed samples
    oracle_run.add_sample(Sample(
        id="ss-oracle-s1", sample_id="SAMPLE-01", sample_name="Sample One",
        index_pair=IndexPair(
            id="sck-p1", name="UDP0001",
            index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    oracle_run.add_sample(Sample(
        id="ss-oracle-s2", sample_id="SAMPLE-02", sample_name="Sample Two",
        index_pair=IndexPair(
            id="sck-p2", name="UDP0002",
            index1=Index(name="i7-02", sequence="TCCGGAGA", index_type=IndexType.I7),
            index2=Index(name="i5-02", sequence="ATAGAGGC", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    oracle_run.add_sample(Sample(
        id="ss-oracle-s3", sample_id="SAMPLE-03", sample_name="Sample Three",
        index_pair=IndexPair(
            id="sck-p3", name="UDP0003",
            index1=Index(name="i7-03", sequence="CGCTCATT", index_type=IndexType.I7),
            index2=Index(name="i5-03", sequence="CCTATCCT", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    # 3 unindexed samples
    oracle_run.add_sample(Sample(
        id="ss-oracle-s4", sample_id="SAMPLE-04", sample_name="Sample Four",
        lanes=[1],
    ))
    oracle_run.add_sample(Sample(
        id="ss-oracle-s5", sample_id="SAMPLE-05", sample_name="Sample Five",
        lanes=[1],
    ))
    oracle_run.add_sample(Sample(
        id="ss-oracle-s6", sample_id="SAMPLE-06", sample_name="Sample Six",
        lanes=[1],
    ))
    ctx.run_repo.save(oracle_run)

    # --- Seed a DRAFT run with index COLLISIONS so the validation heatmap shows dist-0 cells. ---
    # Two samples share the same i7+i5 sequences → Hamming distance 0.
    _t_coll = datetime(2026, 1, 10, 10, 0, 0)
    collision_run = SequencingRun(
        id=COLLISION_RUN_ID,
        run_name="Screenshot collision run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=RunStatus.DRAFT,
        created_by=BROWSER_ADMIN["username"],
        updated_by=BROWSER_ADMIN["username"],
        created_at=_t_coll,
        updated_at=_t_coll,
    )
    _shared_pair_a = IndexPair(
        id="sck-p1", name="UDP0001",
        index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5),
    )
    _shared_pair_b = IndexPair(
        id="sck-p1", name="UDP0001",
        index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5),
    )
    collision_run.add_sample(Sample(
        id="ss-coll-s1", sample_id="COLL-01", sample_name="Collision One",
        index_pair=_shared_pair_a,
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    collision_run.add_sample(Sample(
        id="ss-coll-s2", sample_id="COLL-02", sample_name="Collision Two",
        index_pair=_shared_pair_b,
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    collision_run.add_sample(Sample(
        id="ss-coll-s3", sample_id="COLL-03", sample_name="Collision Three",
        index_pair=IndexPair(
            id="sck-p3", name="UDP0003",
            index1=Index(name="i7-03", sequence="CGCTCATT", index_type=IndexType.I7),
            index2=Index(name="i5-03", sequence="CCTATCCT", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    ctx.run_repo.save(collision_run)

    # --- Seed a READY run (so the Ready dashboard tab is non-empty). ---
    _t_ready = datetime(2026, 1, 10, 11, 0, 0)
    ready_run = SequencingRun(
        id=READY_RUN_ID,
        run_name="Screenshot ready run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=RunStatus.READY,
        created_by=BROWSER_ADMIN["username"],
        updated_by=BROWSER_ADMIN["username"],
        created_at=_t_ready,
        updated_at=_t_ready,
        generated_samplesheet_v2="[Header]\nFileFormatVersion,2\n\n[Reads]\nRead1Cycles,151\n",
        generated_json='{"run_name": "Screenshot ready run"}',
    )
    ready_run.add_sample(Sample(
        id="ss-ready-s1", sample_id="READY-01", sample_name="Ready One",
        index_pair=IndexPair(
            id="sck-p1", name="UDP0001",
            index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
    ))
    ctx.run_repo.save(ready_run)

    # --- Seed an ARCHIVED run (so the Archived dashboard tab is non-empty). ---
    _t_arch = datetime(2026, 1, 10, 12, 0, 0)
    archived_run = SequencingRun(
        id=ARCHIVED_RUN_ID,
        run_name="Screenshot archived run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=RunStatus.ARCHIVED,
        created_by=BROWSER_ADMIN["username"],
        updated_by=BROWSER_ADMIN["username"],
        created_at=_t_arch,
        updated_at=_t_arch,
        generated_samplesheet_v2="[Header]\nFileFormatVersion,2\n\n[Reads]\nRead1Cycles,151\n",
        generated_json='{"run_name": "Screenshot archived run"}',
    )
    archived_run.add_sample(Sample(
        id="ss-arch-s1", sample_id="ARCH-01", sample_name="Archived One",
        index_pair=IndexPair(
            id="sck-p2", name="UDP0002",
            index1=Index(name="i7-02", sequence="TCCGGAGA", index_type=IndexType.I7),
            index2=Index(name="i5-02", sequence="ATAGAGGC", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
    ))
    ctx.run_repo.save(archived_run)

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


@pytest.fixture(scope="session")
def seeded_ids():
    """Fixed run IDs seeded in app_server for screenshot/a11y tests."""
    return {
        "draft_run_id": DRAFT_RUN_ID,
        "screenshot_draft_run_id": SCREENSHOT_DRAFT_RUN_ID,
        "collision_run_id": COLLISION_RUN_ID,
        "ready_run_id": READY_RUN_ID,
        "archived_run_id": ARCHIVED_RUN_ID,
    }


@pytest.fixture(scope="session")
def app_ctx(app_server):
    """The AppContext created by app_server — gives fixtures direct repo access."""
    return _app_ctx


@pytest.fixture
def mutable_run_id(app_ctx):
    """Create a short-lived DRAFT run for mutation tests, then delete it on teardown.

    The run is created directly via the repo (no HTTP), uses a fixed
    created_at/updated_at so it never shows a live timestamp in the DB, and
    is deleted after the test function returns.  Because it exists only for the
    duration of one test, it is invisible to every screenshot/oracle test and
    does not affect the dashboard baseline.

    The run has 3 indexed + 1 unindexed sample — enough for both the
    keyboard-assign test (drop-zone) and the bulk-panel test (checkboxes).
    """
    _t_mut = datetime(2026, 1, 10, 9, 0, 0)
    run_n = next(_mutable_run_counter)
    run_id = f"mutable-run-{run_n:04d}"

    run = SequencingRun(
        id=run_id,
        run_name=f"Mutable test run {run_n}",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=RunStatus.DRAFT,
        created_by=BROWSER_ADMIN["username"],
        updated_by=BROWSER_ADMIN["username"],
        created_at=_t_mut,
        updated_at=_t_mut,
    )
    # 3 indexed samples
    run.add_sample(Sample(
        id=f"{run_id}-s1", sample_id="MUT-01", sample_name="Mutable One",
        index_pair=IndexPair(
            id="sck-p1", name="UDP0001",
            index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    run.add_sample(Sample(
        id=f"{run_id}-s2", sample_id="MUT-02", sample_name="Mutable Two",
        index_pair=IndexPair(
            id="sck-p2", name="UDP0002",
            index1=Index(name="i7-02", sequence="TCCGGAGA", index_type=IndexType.I7),
            index2=Index(name="i5-02", sequence="ATAGAGGC", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    run.add_sample(Sample(
        id=f"{run_id}-s3", sample_id="MUT-03", sample_name="Mutable Three",
        index_pair=IndexPair(
            id="sck-p3", name="UDP0003",
            index1=Index(name="i7-03", sequence="CGCTCATT", index_type=IndexType.I7),
            index2=Index(name="i5-03", sequence="CCTATCCT", index_type=IndexType.I5),
        ),
        index_kit_name=SCREENSHOT_KIT_NAME,
        lanes=[1],
    ))
    # 1 unindexed sample — gives the keyboard-assign test a drop-zone target
    run.add_sample(Sample(
        id=f"{run_id}-s4", sample_id="MUT-04", sample_name="Mutable Four",
        lanes=[1],
    ))

    app_ctx.run_repo.save(run)
    yield run_id
    app_ctx.run_repo.delete(run_id)
