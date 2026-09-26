"""The audit trail must be on without any help from the test runner.

``audit()`` writes at INFO. Nothing in the app raised the audit logger
above Python's default WARNING, so every audit event was dropped. The
tests in ``test_audit_log.py`` did not notice: they raise the level
themselves with ``caplog.set_level``.
"""

import os
import subprocess
import sys
from pathlib import Path


# This checkout's source, so the child imports the code under test and not
# whatever copy of seqsetup the environment would find first.
_SRC = Path(__file__).resolve().parents[2] / "src"


def _run_clean(code: str) -> str:
    """Run code in a fresh interpreter: no pytest, no caplog, no logging
    set-up other than what the app does itself."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(_SRC), env.get("PYTHONPATH", "")) if p
    )
    result = subprocess.run(
        [sys.executable, "-c", f"import seqsetup; assert seqsetup.__file__.startswith({str(_SRC)!r})\n" + code],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


class TestAuditLoggerIsEnabled:
    """An audit event is recorded in a plain Python process."""

    def test_audit_logger_is_enabled_for_info(self):
        out = _run_clean(
            "import logging\n"
            "import seqsetup.services.audit_log\n"
            "print(logging.getLogger('seqsetup.audit').isEnabledFor(logging.INFO))\n"
        )

        assert out == "True"

    def test_audit_event_reaches_the_log_viewer_handler(self):
        out = _run_clean(
            "from seqsetup.services.audit_log import audit\n"
            "from seqsetup.services.log_capture import setup_log_capture\n"
            "handler = setup_log_capture(['seqsetup'])\n"
            "audit('login.success', actor='alice')\n"
            "print(sum('login.success' in e.message for e in handler.get_entries()))\n"
        )

        assert out == "1"

    def test_other_app_info_logs_stay_off(self):
        """Only the audit logger is raised — the rest of the app still logs
        at WARNING and above, as before."""
        out = _run_clean(
            "import logging\n"
            "import seqsetup.services.audit_log\n"
            "print(logging.getLogger('seqsetup.services.github_sync')"
            ".isEnabledFor(logging.INFO))\n"
        )

        assert out == "False"
