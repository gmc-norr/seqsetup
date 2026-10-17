"""A config folder SeqSetup may not look in is said, not read as "no file".

A practice deploy (2026-10-17) cloned the repository on a server whose umask
is 007. The app container runs as another user, so it could not enter the
mounted config/ folder: ``Path.exists`` read that as "no file", the start
logged only a Python warning, and Admin > Instruments said it was "Using
local configuration file (config/instruments.yaml)" while no instrument had
been read.
"""

import logging
import os
import shutil
from pathlib import Path

import pytest

from seqsetup.data import instruments

REAL = Path(__file__).resolve().parents[2] / "config" / "instruments.yaml"

pytestmark = pytest.mark.skipif(
    os.geteuid() == 0, reason="root may enter any folder, so no folder is closed to it")


@pytest.fixture
def module_state():
    """Keep the module's loaded instruments as they were before the test."""
    names = ("_config", "_instruments", "_default_cycles", "_index_cycle_options",
             "_loaded_config_path", "_local_file_problem")
    saved = {name: getattr(instruments, name) for name in names}
    yield
    for name, value in saved.items():
        setattr(instruments, name, value)


@pytest.fixture
def project(tmp_path, monkeypatch, module_state):
    """A checkout of our own: the module reads <root>/config/instruments.yaml,
    and the working directory (its second place to look) holds nothing."""
    root = tmp_path / "checkout"
    (root / "src" / "seqsetup" / "data").mkdir(parents=True)
    (root / "config").mkdir()
    shutil.copy(REAL, root / "config" / "instruments.yaml")
    monkeypatch.setattr(instruments, "__file__",
                        str(root / "src" / "seqsetup" / "data" / "instruments.py"))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    yield root
    (root / "config").chmod(0o755)
    if (root / "config" / "instruments.yaml").exists():
        (root / "config" / "instruments.yaml").chmod(0o644)


class TestAFolderSeqSetupMayNotEnter:

    def test_no_local_instrument_is_loaded_and_the_reason_is_kept(self, project):
        (project / "config").chmod(0o600)
        instruments._initialize_at_start()
        assert instruments._instruments == {}
        problem = instruments.local_instruments_problem()
        assert problem and "may not look in" in problem
        assert str(project / "config") in problem

    def test_the_reason_is_logged_as_a_warning_where_the_log_page_sees_it(self, project, caplog):
        (project / "config").chmod(0o600)
        instruments._initialize_at_start()
        with caplog.at_level(logging.WARNING, logger=instruments.logger.name):
            instruments.log_instruments_file()
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any("may not look in" in r.getMessage() for r in warnings)


class TestTheOtherCasesAreAsBefore:

    def test_a_readable_file_is_read_and_there_is_no_problem(self, project):
        instruments._local_file_problem = "left from a start before"
        instruments._initialize_at_start()
        assert instruments._instruments
        assert instruments.local_instruments_problem() is None

    def test_a_missing_file_is_said_to_be_missing(self, project):
        (project / "config" / "instruments.yaml").unlink()
        instruments._initialize_at_start()
        assert instruments._instruments == {}
        assert "Could not find" in instruments.local_instruments_problem()

    def test_a_file_it_can_see_but_not_open_still_stops_the_start(self, project):
        """Unchanged: the folder can be entered, the file cannot be read."""
        (project / "config" / "instruments.yaml").chmod(0o000)
        with pytest.raises(PermissionError):
            instruments._initialize_at_start()
