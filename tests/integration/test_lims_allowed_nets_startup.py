"""The app's own start-up stops on a LIMS allow-list it cannot use.

``check_lims_allowed_nets`` refuses the value; these tests are about
``seqsetup.app`` calling it, before anything connects or serves. Each one
imports the app module with the variable set, so a release that stopped
calling the check would start happily with a list that allows nothing it
was meant to -- or with the removed variable, which allowed every private
address at once.

Only refusals are tested here: that path never reaches ``init_repos``, so
it leaves nothing behind. That a good or absent list starts the app is what
every other test in this suite depends on.
"""

import importlib
import sys

import pytest


ALLOWED = "SEQSETUP_LIMS_ALLOWED_NETS"
REMOVED = "SEQSETUP_LIMS_ALLOW_PRIVATE_NETS"


@pytest.fixture
def ready_to_import(isolated_mongo, monkeypatch, tmp_path):
    """What seqsetup.app needs at import, minus the two LIMS variables."""
    monkeypatch.setenv("SEQSETUP_SESSION_SECRET", "x" * 64)
    monkeypatch.setattr("seqsetup.startup.SESSKEY_PATH", tmp_path / ".sesskey")
    monkeypatch.delenv(ALLOWED, raising=False)
    monkeypatch.delenv(REMOVED, raising=False)
    sys.modules.pop("seqsetup.app", None)
    yield
    sys.modules.pop("seqsetup.app", None)
    # An import that got past the check would have started the scheduler and
    # pointed the audit sink at this test's database. Put both back.
    import seqsetup.startup as startup_module
    scheduler = getattr(startup_module, "_profile_sync_scheduler", None)
    if scheduler is not None:
        try:
            scheduler.stop()
        except Exception:
            pass
    startup_module._profile_sync_scheduler = None
    from seqsetup.services.audit_log import set_audit_sink
    set_audit_sink(None)


class TestTheStartStops:
    def test_on_a_list_that_is_not_cidr(self, ready_to_import, monkeypatch):
        monkeypatch.setenv(ALLOWED, "not-a-network")
        with pytest.raises(RuntimeError, match=ALLOWED):
            importlib.import_module("seqsetup.app")

    def test_on_a_network_that_reaches_into_a_refused_range(
            self, ready_to_import, monkeypatch):
        monkeypatch.setenv(ALLOWED, "169.0.0.0/8")
        with pytest.raises(RuntimeError, match=r"169\.254\.0\.0/16"):
            importlib.import_module("seqsetup.app")

    def test_on_the_removed_variable(self, ready_to_import, monkeypatch):
        monkeypatch.setenv(REMOVED, "1")
        with pytest.raises(RuntimeError, match=ALLOWED):
            importlib.import_module("seqsetup.app")
