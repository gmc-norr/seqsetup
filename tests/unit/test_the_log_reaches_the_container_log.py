"""SeqSetup's own log lines reach the container log, scrubbed.

In production `pixi run serve` is `python -m seqsetup.app`: the module runs
top to bottom (``setup_log_capture(["seqsetup"])`` puts the Admin > Logs
handler on the ``seqsetup`` logger), then uvicorn gives handlers to the
``uvicorn*`` loggers only. The root logger has none, and because ``seqsetup``
now *has* one, Python's last-resort stderr was never used for a seqsetup
record: every line -- the export files a Mark Ready wrote, an audit event the
database refused, the reason a sign-in was refused 403 -- lived only in a
2,000-entry buffer that a restart empties, and `docker compose logs app`
showed none of it, although CLAUDE.md says of the two ConflictError paths
that "the log line is the record" (review OPSDOCS-1).

And the one stream that did reach the container log, uvicorn's, carried no
scrubbing filter, so an unhandled error's traceback printed a
``mongodb://user:password@`` in full.

The app is imported in a fresh interpreter (no pytest log handlers) with
MongoClient replaced by mongomock: no database is reached.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

SCRIPT = r"""
import logging, mongomock
import seqsetup.services.database as database
database.MongoClient = mongomock.MongoClient
import seqsetup.app as app_module            # what `python -m seqsetup.app` runs
import seqsetup.startup as startup
startup._profile_sync_scheduler.stop()
import uvicorn
uvicorn.Config(app_module.app, host="127.0.0.1", port=5001)   # uvicorn.run's first step

from seqsetup.services import audit_log, run_exports

# 1. The export-file line Mark Ready writes for every file it stored.
run_exports._log_files_written("RUN-PROBE-1", {"samplesheet_v2": {"id": "FILE-PROBE-1"}},
                               "a Mark Ready in progress")

# 2. An audit event the database could not take.
class Down:
    def append(self, entry):
        raise RuntimeError("database unavailable")
audit_log.set_audit_sink(Down())
audit_log.audit("probe.event", actor="probe-user", target="RUN-PROBE-2")

# 3. An unhandled error's traceback, logged the way uvicorn logs one.
try:
    raise RuntimeError("cannot reach mongodb://seqsetup_app:PROBEPASSWORD@mongodb:27017/seqsetup")
except RuntimeError as exc:
    logging.getLogger("uvicorn.error").error("Exception in ASGI application\n", exc_info=exc)

# 4. A sign-in through a TLS proxy before SEQSETUP_TRUSTED_ORIGINS is set: the
#    Origin check refuses it (403) and logs why.
from starlette.testclient import TestClient
answer = TestClient(app_module.app, base_url="http://seqsetup.example.com").post(
    "/login/submit", data={"username": "a", "password": "b"},
    headers={"Origin": "https://seqsetup.example.com"}, follow_redirects=False)
print("LOGIN-STATUS:" + str(answer.status_code))

# 5. The access line uvicorn writes for every request, through uvicorn's own
#    formatter, which unpacks five positional arguments of its own.
logging.getLogger("uvicorn.access").info(
    '%s - "%s %s HTTP/%s" %d', "1.2.3.4:5678", "GET", "/runs/abc", "1.1", 200)

from seqsetup.services.log_capture import get_captured_logs
kept = [e.message for e in get_captured_logs(limit=2000)]
print("ADMIN-LOGS:" + repr([m for m in kept for tag in
                            ("FILE-PROBE-1", "RUN-PROBE-2", "SEQSETUP_TRUSTED_ORIGINS")
                            if tag in m]))
print("BUFFER-COUNT:" + str(sum(1 for m in kept if "FILE-PROBE-1" in m)))
"""


@pytest.fixture(scope="module")
def started(tmp_path_factory):
    env = dict(os.environ)
    env.update({
        "MONGODB_URI": "mongodb://127.0.0.1:1",
        "PYTHONPATH": str(ROOT / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "SEQSETUP_SESSION_SECRET": "x" * 64,
    })
    env.pop("TZ", None)
    done = subprocess.run([sys.executable, "-c", SCRIPT], cwd=tmp_path_factory.mktemp("run"),
                          env=env, capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, done.stderr[-2000:]
    marks = ("ADMIN-LOGS:", "LOGIN-STATUS:", "BUFFER-COUNT:")
    said = {m: [l for l in done.stdout.splitlines() if l.startswith(m)][0] for m in marks}
    # What `docker compose logs app` shows: the process's stdout and stderr.
    container_log = "\n".join(l for l in (done.stdout + done.stderr).splitlines()
                              if not l.startswith(marks))
    return said, container_log


class TestEveryLineIsKeptSomewhereLasting:

    def test_the_export_files_a_mark_ready_wrote(self, started):
        said, container_log = started

        assert "FILE-PROBE-1" in said["ADMIN-LOGS:"]       # Admin > Logs has it
        assert "FILE-PROBE-1" in container_log, container_log[-2000:]

    def test_an_audit_event_the_database_refused(self, started):
        said, container_log = started

        assert "RUN-PROBE-2" in said["ADMIN-LOGS:"]
        assert "RUN-PROBE-2" in container_log, container_log[-2000:]

    def test_why_a_sign_in_was_refused(self, started):
        """Admin > Logs cannot be opened without signing in, so the reason a
        sign-in is refused has to be somewhere else as well."""
        said, container_log = started

        assert said["LOGIN-STATUS:"] == "LOGIN-STATUS:403"
        assert "SEQSETUP_TRUSTED_ORIGINS" in said["ADMIN-LOGS:"]
        assert "SEQSETUP_TRUSTED_ORIGINS" in container_log, container_log[-2000:]

    def test_no_line_is_written_to_the_buffer_twice(self, started):
        said, _container_log = started

        assert said["BUFFER-COUNT:"] == "BUFFER-COUNT:1", said["BUFFER-COUNT:"]


class TestTheWebServersOwnLinesStillWork:

    def test_the_access_line_of_every_request(self, started):
        """uvicorn's AccessFormatter renders the line from five positional
        arguments. A filter that clears record.args after rendering the
        message made that formatter raise, so every request wrote a
        logging-error traceback instead of its access line."""
        _said, container_log = started

        assert '"GET /runs/abc HTTP/1.1" 200' in container_log, container_log[-1500:]
        assert "--- Logging error ---" not in container_log, [
            l for l in container_log.splitlines() if "Logging error" in l]
        assert "not enough values to unpack" not in container_log


class TestTheContainerLogIsScrubbed:

    def test_an_unhandled_tracebacks_password(self, started):
        _said, container_log = started

        assert "Exception in ASGI application" in container_log
        assert "PROBEPASSWORD" not in container_log, [
            l for l in container_log.splitlines() if "PROBEPASSWORD" in l][:2]
