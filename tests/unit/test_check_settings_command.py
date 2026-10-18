"""``pixi run check-settings <folder>``: the lab checks its settings folder with
the rules the sync uses, before a sync and with no running app
(docs/design/2026-10-18-input-rules-design.md, "7. The settings command").

It needs no database, no network and no app start-up, so it is run here in a
fresh process with a broken INSTRUMENTS_CONFIG and an unreachable database:
importing the app's start-up would read that file and stop.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "config"
GOOD = (CONFIG / "instruments" / "miseq.yaml").read_text()


def _run(*args, probe=False):
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"),
           "INSTRUMENTS_CONFIG": "/nonexistent/instruments.yaml",
           "MONGODB_URI": "mongodb://127.0.0.1:1"}
    if probe:
        code = (
            "import sys\n"
            "from seqsetup.input_rules import cli\n"
            f"status = cli.main({list(args)!r})\n"
            "loaded = [m for m in ('seqsetup.data.instruments', 'seqsetup.services.github_sync',"
            " 'seqsetup.startup', 'pymongo.mongo_client') if m in sys.modules]\n"
            "print('LOADED', loaded)\n"
            "sys.exit(status)\n"
        )
        command = [sys.executable, "-c", code]
    else:
        command = [sys.executable, "-m", "seqsetup.input_rules.cli", *args]
    return subprocess.run(command, capture_output=True, text=True, env=env, timeout=120)


def _folder(tmp_path, files: dict) -> Path:
    for name, text in files.items():
        path = tmp_path / "instruments" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


class TestTheShippedSettings:

    def test_pass(self):
        done = _run(str(CONFIG), "--local-instruments", str(CONFIG / "instruments.yaml"))

        assert done.returncode == 0, done.stdout + done.stderr
        assert done.stdout == ""
        assert "12 files checked, no errors" in done.stderr


class TestAFolderWithProblems:

    def test_each_problem_has_its_file_line_and_place_and_the_command_fails(self, tmp_path):
        folder = _folder(tmp_path, {"good.yaml": GOOD, "sub/bad.yaml": GOOD + "lane: 2\n"})

        done = _run(str(folder))

        assert done.returncode == 1
        line = len(GOOD.splitlines()) + 1
        assert done.stdout.splitlines() == [
            f"instruments/sub/bad.yaml:{line}:1: lane: is not a key this file can have (check the spelling)"
        ]
        assert "2 files checked, 1 error" in done.stderr

    def test_two_files_for_one_instrument(self, tmp_path):
        folder = _folder(tmp_path, {"a.yaml": GOOD, "b.yaml": GOOD})

        done = _run(str(folder))

        assert done.returncode == 1
        assert "a.yaml and b.yaml both give name 'MiSeq'" in done.stdout

    def test_a_warning_is_marked_and_does_not_fail(self, tmp_path):
        nx = (CONFIG / "instruments" / "novaseq-x-series.yaml").read_text()
        teal = nx.replace('dye_channels: ["Blue", "Green"]', 'dye_channels: ["Blue", "Teal"]')
        assert teal != nx
        folder = _folder(tmp_path, {"nx.yaml": teal})

        done = _run(str(folder))

        assert done.returncode == 0
        assert "warning: dye_channels > item 2:" in done.stdout

    def test_a_broken_local_file(self, tmp_path):
        local = tmp_path / "instruments.yaml"
        local.write_text((CONFIG / "instruments.yaml").read_text().replace("index_cycle_options:", "index_cycle_option:"))
        folder = _folder(tmp_path, {"good.yaml": GOOD})

        done = _run(str(folder), "--local-instruments", str(local))

        assert done.returncode == 1
        assert "instruments.yaml:" in done.stdout and "index_cycle_option: is not a key" in done.stdout

    def test_a_folder_that_is_not_there(self, tmp_path):
        done = _run(str(tmp_path / "missing"))

        assert done.returncode == 2
        assert "is not a folder" in done.stderr


class TestItReadsWhatTheSyncReads:
    """A command that passes having checked nothing, or checks files the sync
    never reads, tells the lab its settings are fine when they are not."""

    def test_a_settings_folder_with_no_instrument_folder_fails(self, tmp_path):
        done = _run(str(tmp_path))

        assert done.returncode == 1
        assert done.stdout.splitlines() == ["instruments/: is not there (name the folder with --instruments)"]
        assert "0 files checked, 1 error" in done.stderr

    def test_an_instrument_folder_with_no_instrument_file_fails(self, tmp_path):
        (tmp_path / "instruments").mkdir()
        (tmp_path / "instruments" / "README.md").write_text("notes\n")

        done = _run(str(tmp_path))

        assert done.returncode == 1
        assert done.stdout.splitlines() == ["instruments/: holds no instrument file (.yaml or .yml)"]

    def test_a_link_is_skipped_as_the_sync_skips_it(self, tmp_path):
        folder = _folder(tmp_path, {"a.yaml": GOOD})
        (folder / "instruments" / "b.yaml").symlink_to(folder / "instruments" / "a.yaml")
        (folder / "instruments" / "sub").symlink_to(folder / "instruments", target_is_directory=True)

        done = _run(str(folder))

        assert done.returncode == 0, done.stdout
        assert "1 files checked, no errors" in done.stderr

    def test_a_file_named_just_dot_yaml_is_read_as_the_sync_reads_it(self, tmp_path):
        folder = _folder(tmp_path, {".yaml": GOOD + "lane: 2\n"})

        done = _run(str(folder))

        assert done.returncode == 1
        assert done.stdout.startswith("instruments/.yaml:")

    def test_an_instrument_folder_outside_the_settings_folder_is_refused(self, tmp_path):
        _folder(tmp_path / "settings", {"a.yaml": GOOD})

        done = _run(str(tmp_path / "settings"), "--instruments", "../elsewhere")

        assert done.returncode == 2
        assert "inside" in done.stderr

    def test_a_file_the_parser_cannot_take_in_does_not_stop_the_others(self, tmp_path):
        folder = _folder(tmp_path, {"a.yaml": GOOD.replace("MiSeq", "Mi\x0cSeq", 1), "b.yaml": GOOD + "lane: 2\n"})

        done = _run(str(folder))

        assert done.returncode == 1
        assert [line.split(":")[0] for line in done.stdout.splitlines()] == [
            "instruments/a.yaml", "instruments/b.yaml"]
        assert "2 files checked, 2 errors" in done.stderr


class TestItNeedsNoApp:

    def test_no_start_up_module_and_no_database_client_is_loaded(self):
        done = _run(str(CONFIG), probe=True)

        assert done.returncode == 0, done.stdout + done.stderr
        assert "LOADED []" in done.stdout


class TestJsonSchemas:

    def test_one_per_document_each_refusing_unknown_keys(self, tmp_path):
        done = _run("--schema", str(tmp_path))

        assert done.returncode == 0, done.stderr
        written = sorted(p.name for p in tmp_path.iterdir())
        assert written == ["instrument.schema.json", "instruments-file.schema.json",
                           "local-instruments.schema.json"]
        for name in written:
            schema = json.loads((tmp_path / name).read_text())
            assert schema["additionalProperties"] is False, name
            assert "authority" in schema["description"]


class TestThePixiTask:

    def test_is_defined(self):
        assert 'check-settings = "PYTHONPATH=src python -m seqsetup.input_rules.cli"' in (
            REPO / "pixi.toml").read_text()
