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
            " 'seqsetup.startup', 'pymongo.mongo_client', 'seqsetup.services.sheet_plan',"
            " 'seqsetup.services.cycle_calculator') if m in sys.modules]\n"
            "print('LOADED', loaded)\n"
            "sys.exit(status)\n"
        )
        command = [sys.executable, "-c", code]
    else:
        command = [sys.executable, "-m", "seqsetup.input_rules.cli", *args]
    return subprocess.run(command, capture_output=True, text=True, env=env, timeout=120)


PROFILES = {
    "profiles/application_profiles/BCLConvertNextera.yaml":
        (CONFIG / "profiles" / "application_profiles" / "dragen" / "BCLConvertNextera.yaml").read_text(),
    "profiles/test_profiles/Wgs.yaml": (CONFIG / "profiles" / "test_profiles" / "Wgs.yaml").read_text(),
}


def _folder(tmp_path, files: dict, profiles: bool = True) -> Path:
    """A settings folder with ``files`` in instruments/ and, unless told
    otherwise, one good application profile and one good test profile."""
    for name, text in files.items():
        path = tmp_path / "instruments" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for name, text in (PROFILES if profiles else {}).items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


class TestTheShippedSettings:

    def test_pass(self):
        done = _run(str(CONFIG), "--local-instruments", str(CONFIG / "instruments.yaml"))

        assert done.returncode == 0, done.stdout + done.stderr
        assert done.stdout == ""
        assert "19 files checked, no errors" in done.stderr


class TestAFolderWithProblems:

    def test_each_problem_has_its_file_line_and_place_and_the_command_fails(self, tmp_path):
        folder = _folder(tmp_path, {"good.yaml": GOOD, "sub/bad.yaml": GOOD + "lane: 2\n"})

        done = _run(str(folder))

        assert done.returncode == 1
        line = len(GOOD.splitlines()) + 1
        assert done.stdout.splitlines() == [
            f"instruments/sub/bad.yaml:{line}:1: lane: is not a key this file can have (check the spelling)"
        ]
        assert "4 files checked, 1 error" in done.stderr

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
        done = _run(str(_folder(tmp_path, {})))

        assert done.returncode == 1
        assert done.stdout.splitlines() == [
            "instruments/: is not there (name the folder with --instruments, "
            "or say --no-instruments when the sync does not read instruments)"]
        assert "2 files checked, 1 error" in done.stderr

    def test_an_instrument_folder_with_no_instrument_file_fails(self, tmp_path):
        _folder(tmp_path, {})
        (tmp_path / "instruments").mkdir()
        (tmp_path / "instruments" / "README.md").write_text("notes\n")

        done = _run(str(tmp_path))

        assert done.returncode == 1
        assert done.stdout.splitlines() == ["instruments/: holds no instrument file (.yaml or .yml)"]

    def test_a_link_to_a_file_is_read_as_github_serves_it(self, tmp_path):
        """GitHub lists a link to a file as a file and serves the link's
        target path as its text, so the sync refuses a linked instrument
        file. Skipping it here once passed what the sync refuses."""
        folder = _folder(tmp_path, {"a.yaml": GOOD})
        (folder / "instruments" / "b.yaml").symlink_to("a.yaml")

        done = _run(str(folder))

        assert done.returncode == 1
        assert done.stdout.splitlines() == [
            "instruments/b.yaml:1:1: the file: must be a map of keys and values"]
        assert "4 files checked, 1 error" in done.stderr

    def test_a_link_to_a_folder_is_skipped_as_the_sync_skips_it(self, tmp_path):
        """GitHub lists a link to a folder as a link, which the sync skips."""
        folder = _folder(tmp_path, {"a.yaml": GOOD})
        (folder / "instruments" / "sub").symlink_to(folder / "instruments", target_is_directory=True)
        (folder / "instruments" / "old.yaml").symlink_to(folder / "instruments", target_is_directory=True)

        done = _run(str(folder))

        assert done.returncode == 0, done.stdout
        assert "3 files checked, no errors" in done.stderr

    @pytest.mark.skipif(os.geteuid() == 0, reason="root reads a folder of mode 000")
    def test_a_sub_folder_that_cannot_be_read_fails(self, tmp_path):
        """A folder skipped without a word would leave its files unchecked
        while the command said it found no errors (the fresh review of
        b21ea6f, P3 8)."""
        folder = _folder(tmp_path, {"a.yaml": GOOD})
        locked = folder / "profiles" / "test_profiles" / "locked"
        locked.mkdir()
        (locked / "Bad.yaml").write_text("TestType: 5\n")
        locked.chmod(0)
        try:
            done = _run(str(folder))
        finally:
            locked.chmod(0o755)

        assert done.returncode == 1
        assert done.stdout.splitlines() == [
            "profiles/test_profiles/locked/: could not be read, so its files were not checked"]

    def test_a_git_submodule_is_not_read_as_the_sync_does_not_read_it(self, tmp_path):
        """GitHub lists a submodule as one entry with no download link, never
        the files inside it (the fresh review of b21ea6f, P3 8)."""
        folder = _folder(tmp_path, {"a.yaml": GOOD})
        shared = folder / "profiles" / "test_profiles" / "shared"
        shared.mkdir()
        (shared / ".git").write_text("gitdir: ../../../.git/modules/shared\n")
        (shared / "Bad.yaml").write_text("TestType: 5\n")

        done = _run(str(folder))

        assert done.returncode == 0, done.stdout
        assert "3 files checked, no errors" in done.stderr

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
        assert "4 files checked, 2 errors" in done.stderr


class TestProfiles:
    """The command checks both profile folders with the rules the sync uses
    (docs/design/2026-10-18-input-rules-design.md, step 2)."""

    def test_a_refused_test_profile_is_named_with_its_line(self, tmp_path):
        folder = _folder(tmp_path, {"good.yaml": GOOD})
        wgs = folder / "profiles" / "test_profiles" / "Wgs.yaml"
        wgs.write_text(wgs.read_text().replace("TestType: WGS", "TestType: 5"))

        done = _run(str(folder))

        assert done.returncode == 1
        assert done.stdout.splitlines() == [
            "profiles/test_profiles/Wgs.yaml:2:11: TestType: must be text: put it in quotes"]

    def test_an_unknown_key_in_an_application_profile(self, tmp_path):
        folder = _folder(tmp_path, {"good.yaml": GOOD})
        app = folder / "profiles" / "application_profiles" / "BCLConvertNextera.yaml"
        app.write_text(app.read_text() + "Setings:\n  X: 1\n")

        done = _run(str(folder))

        assert done.returncode == 1
        assert "profiles/application_profiles/BCLConvertNextera.yaml:" in done.stdout
        assert "Setings: is not a key this file can have" in done.stdout

    def test_a_profile_ending_in_capitals_is_read_as_the_sync_reads_it(self, tmp_path):
        folder = _folder(tmp_path, {"good.yaml": GOOD})
        (folder / "profiles" / "test_profiles" / "Other.YAML").write_text("TestType: 5\n")

        done = _run(str(folder))

        assert done.returncode == 1
        assert "profiles/test_profiles/Other.YAML:" in done.stdout

    def test_two_files_for_one_test_and_version(self, tmp_path):
        folder = _folder(tmp_path, {"good.yaml": GOOD})
        (folder / "profiles" / "test_profiles" / "sub").mkdir()
        (folder / "profiles" / "test_profiles" / "sub" / "Wgs.yaml").write_text(
            PROFILES["profiles/test_profiles/Wgs.yaml"])

        done = _run(str(folder))

        assert done.returncode == 1
        assert done.stdout.splitlines() == [
            "profiles/test_profiles/: WGS 1.0.0 is in profiles/test_profiles/Wgs.yaml and "
            "profiles/test_profiles/sub/Wgs.yaml"]

    def test_an_application_profile_ending_in_capitals_is_read_too(self, tmp_path):
        folder = _folder(tmp_path, {"good.yaml": GOOD})
        (folder / "profiles" / "application_profiles" / "Other.YAML").write_text(
            "ApplicationProfileName: 5\n")

        done = _run(str(folder))

        assert done.returncode == 1
        assert "profiles/application_profiles/Other.YAML:1:25: ApplicationProfileName: " in done.stdout

    def test_two_files_for_one_application_profile_and_version(self, tmp_path):
        """The fresh review of b21ea6f, P3 3: skipping this check passed every test."""
        folder = _folder(tmp_path, {"good.yaml": GOOD})
        (folder / "profiles" / "application_profiles" / "sub").mkdir()
        (folder / "profiles" / "application_profiles" / "sub" / "Copy.yaml").write_text(
            PROFILES["profiles/application_profiles/BCLConvertNextera.yaml"])

        done = _run(str(folder))

        assert done.returncode == 1
        assert done.stdout.splitlines() == [
            "profiles/application_profiles/: BCLConvertNextera 1.0.0 is in "
            "profiles/application_profiles/BCLConvertNextera.yaml and "
            "profiles/application_profiles/sub/Copy.yaml; a profile name and version may be "
            "in one file only"]

    def test_a_missing_profile_folder_fails(self, tmp_path):
        folder = _folder(tmp_path, {"good.yaml": GOOD}, profiles=False)

        done = _run(str(folder))

        assert done.returncode == 1
        assert done.stdout.splitlines() == [
            "profiles/application_profiles/: is not there (name the folder with --application-profiles)",
            "profiles/test_profiles/: is not there (name the folder with --test-profiles)",
        ]

    def test_a_lab_that_does_not_sync_instruments(self, tmp_path):
        done = _run(str(_folder(tmp_path, {})), "--no-instruments")

        assert done.returncode == 0, done.stdout
        assert "2 files checked, no errors" in done.stderr


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
        assert written == ["application-profile.schema.json", "instrument.schema.json",
                           "instruments-file.schema.json", "local-instruments.schema.json",
                           "test-profile.schema.json"]
        for name in written:
            schema = json.loads((tmp_path / name).read_text())
            assert schema["additionalProperties"] is False, name
            assert "authority" in schema["description"]


class TestThePixiTask:

    def test_is_defined(self):
        assert 'check-settings = "PYTHONPATH=src python -m seqsetup.input_rules.cli"' in (
            REPO / "pixi.toml").read_text()
