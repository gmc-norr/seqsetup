"""Group A4: test versions (spec 2026-10-07 group A4), through the app."""

import pytest

from .test_sheet_followups import _SYNC_LOGGER, _Messages, _app_profile_yaml


def _test_yaml(version: str, test: str = "WGS") -> str:
    return (
        f"TestType: {test}\n"
        f"TestName: {test}\n"
        "Description: Whole genome\n"
        f'Version: "{version}"\n'
        "ApplicationProfiles:\n"
        "  - ApplicationProfileName: GuardProfile\n"
        '    ApplicationProfileVersion: "1.0.0"\n'
    )


def _fake_github(ctx, monkeypatch, test_files: dict, app_files: dict | None = None,
                 instrument_files: dict | None = None):
    """The sync service, with a repository whose test-profile folder holds
    ``test_files``; only the GitHub fetches are replaced. A value in a folder
    is a file's text; a dict, a sub-folder; an exception, a sub-folder whose
    listing raises it; None, a file with no download link."""
    config = ctx.profile_sync_config_repo.get()
    config.github_repo_url = "https://github.com/example/config"
    config.sync_instruments_enabled = instrument_files is not None
    config.sync_index_kits_enabled = False
    ctx.profile_sync_config_repo.save(config)
    folders = {
        config.application_profiles_path.strip("/"): app_files or {
            "Guard.yaml": _app_profile_yaml("GuardProfile", '"4.3.6"')},
        config.test_profiles_path.strip("/"): test_files,
    }
    if instrument_files is not None:
        folders[config.instruments_path.strip("/")] = instrument_files
    texts = {}

    def listing(owner, repo, branch, path):
        path = path.strip("/")
        if isinstance(folders[path], Exception):
            raise folders[path]
        entries = []
        for name, value in folders[path].items():
            item_path = f"{path}/{name}"
            if isinstance(value, (dict, Exception)):
                folders[item_path] = value
                entries.append({"type": "dir", "name": name, "path": item_path})
            elif value is None:
                entries.append({"type": "file", "name": name, "path": item_path})
            else:
                url = f"https://raw.githubusercontent.com/example/config/main/{item_path}"
                texts[url] = value
                entries.append({"type": "file", "name": name, "path": item_path,
                                "download_url": url})
        return entries

    service = ctx.get_github_sync_service()
    monkeypatch.setattr(service, "_fetch_directory_contents", listing)
    monkeypatch.setattr(service, "_fetch_file_content", lambda url: texts[url])
    return service


def _sync_tests(ctx, monkeypatch, test_files: dict, app_files: dict | None = None,
                instrument_files: dict | None = None):
    """One config sync through ``_fake_github``. Returns (ok, message, log
    messages)."""
    service = _fake_github(ctx, monkeypatch, test_files, app_files, instrument_files)
    handler = _Messages()
    _SYNC_LOGGER.addHandler(handler)
    try:
        ok, message, _count = service.sync()
    finally:
        _SYNC_LOGGER.removeHandler(handler)
    return ok, message, handler.messages


def _stored(ctx) -> list[tuple[str, str, str]]:
    return sorted((p.test_type, p.version, p.source_file) for p in ctx.test_profile_repo.list_all())


TESTS_BEFORE = {"Wgs_1.1.yaml": _test_yaml("1.1.0"), "Wgs_1.2.yaml": _test_yaml("1.2.0"),
                "Rna.yaml": _test_yaml("1.0.0", "RNA")}
STORED_BEFORE = [("RNA", "1.0.0", "Rna.yaml"), ("WGS", "1.1.0", "Wgs_1.1.yaml"),
                 ("WGS", "1.2.0", "Wgs_1.2.yaml")]
REFUSED = ("Test profile files were refused, so no test profiles were stored and the stored "
           "ones are kept: ")
FOLDER = "profiles/test_profiles"


class TestATestFileEndingInAnyCase:
    """A test file's .yaml or .yml ending is read in any case; any other
    file is skipped, as today (spec §1, decision 9)."""

    def test_capital_endings_are_read(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            **TESTS_BEFORE, "Wgs_1.3.YAML": _test_yaml("1.3.0"), "Pan.Yml": _test_yaml("1.0.0", "PAN")})
        assert ok, message
        assert _stored(ctx) == [("PAN", "1.0.0", "Pan.Yml")] + STORED_BEFORE + [
            ("WGS", "1.3.0", "Wgs_1.3.YAML")]

    def test_another_file_is_still_skipped(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            **TESTS_BEFORE, "README.md": "# Test profiles\n"})
        assert ok, message
        assert _stored(ctx) == STORED_BEFORE

    def test_an_application_profile_file_still_needs_a_lower_case_ending(self, fresh_app,
                                                                         monkeypatch):
        # Only the test profile folder reads any case (plan review of 8b17009).
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE, app_files={
            "Guard.yaml": _app_profile_yaml("GuardProfile", '"4.3.6"'),
            "Other.YAML": _app_profile_yaml("OtherProfile", '"4.3.6"')})
        assert ok, message
        assert [p.name for p in ctx.app_profile_repo.list_all()] == ["GuardProfile"]


def _last_sync(page: str) -> str:
    """The config-sync page from its last-sync element to the config form."""
    start = page.index('<div id="last-sync"')
    return page[start:page.index("<form", start)]


def _sync_result(page: str) -> str:
    """The config-sync page's result box, tags included."""
    start = page.index('<div id="sync-result"')
    return page[start:page.index("</div>", start) + 6]


class TestTheConfigSyncPageShowsTheLastSync:
    """The config-sync page shows the last sync's time, status and message,
    red on an error; a manual sync's result is red when the sync did not
    succeed (spec §1, decision 10)."""

    RED = "bg-red-100 border border-red-400 text-red-800"
    GREEN = "bg-green-100 border border-green-400 text-green-800"

    def test_before_the_first_sync(self, logged_in_client, fresh_app):
        line = _last_sync(logged_in_client.get("/admin/config-sync").text)
        assert "<strong>Last sync:</strong> —</div>" in line
        assert self.RED not in line

    def test_after_a_refused_sync(self, logged_in_client, fresh_app, monkeypatch):
        from markupsafe import escape
        from seqsetup.utils.clock import local_time
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {"Wgs.yaml": _test_yaml("1.0")})
        assert not ok
        when = local_time(ctx.profile_sync_config_repo.get().last_sync_at)
        line = _last_sync(logged_in_client.get("/admin/config-sync").text)
        assert f'<div id="last-sync" class="{self.RED} rounded px-3 py-2">' in line
        assert f"<strong>Last sync:</strong> {when} (error)</div>" in line
        assert f"<div>{escape(message)}</div>" in line
        assert message.startswith(REFUSED)

    def test_after_a_good_sync(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message
        line = _last_sync(logged_in_client.get("/admin/config-sync").text)
        assert "(success)</div>" in line
        assert "<div>Synced 1 application profiles, 3 test profiles</div>" in line
        assert self.RED not in line

    def test_a_manual_sync_that_refused_files_is_red(self, logged_in_client, fresh_app, monkeypatch):
        from .test_paste_preview import ORIGIN
        _app, ctx, _db = fresh_app
        _fake_github(ctx, monkeypatch, {"Wgs.yaml": _test_yaml("1.0")})
        resp = logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)
        assert resp.status_code == 200
        box = _sync_result(resp.text)
        assert self.RED in box and self.GREEN not in box
        assert REFUSED in box

    def test_a_manual_sync_that_succeeded_is_green(self, logged_in_client, fresh_app, monkeypatch):
        from .test_paste_preview import ORIGIN
        _app, ctx, _db = fresh_app
        _fake_github(ctx, monkeypatch, TESTS_BEFORE)
        resp = logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)
        box = _sync_result(resp.text)
        assert self.GREEN in box and self.RED not in box
        assert "Synced 1 application profiles, 3 test profiles" in box

    def test_no_sync_service_is_red(self, logged_in_client, fresh_app, monkeypatch):
        import dataclasses
        from seqsetup.routes import dependencies
        from .test_paste_preview import ORIGIN
        real = dependencies.get_app_context
        monkeypatch.setattr(dependencies, "get_app_context",
                            lambda: dataclasses.replace(real(), get_github_sync_service=None))
        box = _sync_result(logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN).text)
        assert self.RED in box and "Sync service not available" in box

    def test_a_saved_configuration_is_still_green(self, logged_in_client, fresh_app):
        from .test_paste_preview import ORIGIN
        resp = logged_in_client.post("/admin/config-sync/config", headers=ORIGIN,
                                     data={"github_branch": "main"})
        box = _sync_result(resp.text)
        assert self.GREEN in box and "Configuration saved" in box


class TestTheSyncRefusesATestVersionInTwoFiles:
    """One test and version in more than one file: every such file is
    refused and logged (spec §1)."""

    def test_both_files_are_refused_and_logged(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, logged = _sync_tests(ctx, monkeypatch, {
            "Wgs_a.yaml": _test_yaml("1.2.0"), "Wgs_b.yaml": _test_yaml("1.2.0"),
            "Wgs_new.yaml": _test_yaml("1.3.0"), "Rna.yaml": _test_yaml("1.2.0", "RNA"),
        })
        assert ok is False
        assert message == (REFUSED + "WGS 1.2.0 is in Wgs_a.yaml and Wgs_b.yaml. "
                           "Synced 1 application profiles.")
        assert ("Test profiles refused: WGS 1.2.0 is in Wgs_a.yaml and Wgs_b.yaml. "
                "A test and version may be in one file only.") in logged

    def test_three_files_are_named(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, logged = _sync_tests(ctx, monkeypatch, {
            "C.yaml": _test_yaml("2.0.0"), "A.yaml": _test_yaml("2.0.0"),
            "B.yaml": _test_yaml("2.0.0"), "Rna.yaml": _test_yaml("1.0.0", "RNA"),
        })
        assert ok is False
        assert message == (REFUSED + "WGS 2.0.0 is in A.yaml, B.yaml and C.yaml. "
                           "Synced 1 application profiles.")
        assert ("Test profiles refused: WGS 2.0.0 is in A.yaml, B.yaml and C.yaml. "
                "A test and version may be in one file only.") in logged

    def test_the_same_version_of_two_tests_is_not_a_repeat(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, logged = _sync_tests(ctx, monkeypatch, {
            "Wgs.yaml": _test_yaml("1.0.0"), "Rna.yaml": _test_yaml("1.0.0", "RNA"),
        })
        assert ok, message
        assert _stored(ctx) == [("RNA", "1.0.0", "Rna.yaml"), ("WGS", "1.0.0", "Wgs.yaml")]
        assert not any("Test profiles refused" in m for m in logged)


class TestARefusedTestFileKeepsTheStoredTestProfiles:
    """Any refused test file: no test profile is stored and the stored ones
    are kept, so a sample's 1 still finds the version it found before; the
    sync ends with status error and names the files (spec §1, decision 4)."""

    def _sync_again(self, ctx, monkeypatch, files: dict) -> tuple[str, list[str]]:
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message
        assert _stored(ctx) == STORED_BEFORE
        ok, message, logged = _sync_tests(ctx, monkeypatch, {**TESTS_BEFORE, **files})
        assert ok is False
        assert _stored(ctx) == STORED_BEFORE
        status = ctx.profile_sync_config_repo.get()
        assert (status.last_sync_status, status.last_sync_message) == ("error", message)
        assert status.last_sync_count == 1  # the application profile; no test profile stored
        return message, logged

    def test_a_test_and_version_in_two_files(self, fresh_app, monkeypatch):
        # The newest file repeated: without the rule, 1 would give 1.1.0.
        _app, ctx, _db = fresh_app
        message, _logged = self._sync_again(ctx, monkeypatch, {"Wgs_1.3.yaml": _test_yaml("1.2.0")})
        assert message == (REFUSED + "WGS 1.2.0 is in Wgs_1.2.yaml and Wgs_1.3.yaml. "
                           "Synced 1 application profiles.")

    def test_a_version_that_is_not_three_numbers(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        message, logged = self._sync_again(ctx, monkeypatch, {"Wgs_1.3.yaml": _test_yaml("1.3")})
        assert message == (
            REFUSED + f"{FOLDER}/Wgs_1.3.yaml: Profile validation failed for 'Wgs_1.3.yaml': "
            "Field 'Version' must be three whole numbers joined by dots, each at most 9 digits, "
            "like 1.0.0: '1.3'. Synced 1 application profiles.")
        assert any("Wgs_1.3.yaml" in m and "Field 'Version' must be three whole numbers" in m
                   for m in logged), logged

    def test_yaml_that_cannot_be_read(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        message, _logged = self._sync_again(ctx, monkeypatch, {"Bad.yaml": "TestType: [WGS\n"})
        assert message.startswith(REFUSED + f"{FOLDER}/Bad.yaml: cannot be read as YAML: ")
        assert message.endswith(". Synced 1 application profiles.")

    def test_an_empty_file(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        message, _logged = self._sync_again(ctx, monkeypatch, {"Empty.yaml": "# not yet\n"})
        assert message == REFUSED + f"{FOLDER}/Empty.yaml: is empty. Synced 1 application profiles."

    def test_a_file_with_no_download_link(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        message, _logged = self._sync_again(ctx, monkeypatch, {"Wgs_1.3.yaml": None})
        assert message == (REFUSED + f"{FOLDER}/Wgs_1.3.yaml: has no download link. "
                           "Synced 1 application profiles.")

    def test_a_sub_folder_that_cannot_be_listed(self, fresh_app, monkeypatch):
        from seqsetup.services.github_sync import GitHubSyncError
        _app, ctx, _db = fresh_app
        message, _logged = self._sync_again(ctx, monkeypatch, {
            "new": GitHubSyncError("GitHub API error: 500 Server Error")})
        assert message == (REFUSED + f"{FOLDER}/new/: could not be listed: GitHub API error: "
                           "500 Server Error. Synced 1 application profiles.")

    def test_a_file_in_a_sub_folder(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        message, _logged = self._sync_again(ctx, monkeypatch, {
            "new": {"Wgs_1.3.yaml": _test_yaml("1.3")}})
        assert message.startswith(
            REFUSED + f"{FOLDER}/new/Wgs_1.3.yaml: Profile validation failed for 'Wgs_1.3.yaml'")

    def test_the_application_profiles_are_still_stored(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message
        ok, message, _logged = _sync_tests(
            ctx, monkeypatch, {**TESTS_BEFORE, "Old.yaml": _test_yaml("1.0", "RNA")},
            app_files={"Guard.yaml": _app_profile_yaml("GuardProfile", '"4.3.6"'),
                       "Other.yaml": _app_profile_yaml("OtherProfile", '"4.3.6"')})
        assert ok is False
        assert sorted(p.name for p in ctx.app_profile_repo.list_all()) == [
            "GuardProfile", "OtherProfile"]
        assert message.endswith(". Synced 2 application profiles.")
        assert _stored(ctx) == STORED_BEFORE

    def test_with_refused_instrument_files_too(self, fresh_app, monkeypatch):
        from .test_group_a2 import GOOD_FILES
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(
            ctx, monkeypatch, {**TESTS_BEFORE, "Empty.yaml": ""},
            instrument_files={**GOOD_FILES, "bad.yaml": "name: [\n"})
        assert ok is False
        assert message.startswith(
            REFUSED + f"{FOLDER}/Empty.yaml: is empty. Instrument files were refused, so no "
            "instrument settings were stored and the stored ones are kept: "
            "instruments/bad.yaml: cannot be read as YAML: ")
        assert message.endswith(". Synced 1 application profiles.")
        assert _stored(ctx) == []
        assert ctx.instrument_definition_repo.collection.count_documents({}) == 0

    def test_instruments_are_still_stored(self, fresh_app, monkeypatch):
        from .test_group_a2 import GOOD_FILES
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {**TESTS_BEFORE, "Empty.yaml": ""},
                                           instrument_files=GOOD_FILES)
        assert ok is False
        assert message == (REFUSED + f"{FOLDER}/Empty.yaml: is empty. "
                           "Synced 1 application profiles, 2 instruments.")
        assert ctx.instrument_definition_repo.collection.count_documents({}) == 2
        status = ctx.profile_sync_config_repo.get()
        assert (status.last_sync_count, status.last_instruments_sync_count) == (1, 2)

    def test_a_folder_whose_only_file_is_refused(self, fresh_app, monkeypatch):
        # Named as refused, not stopped by the guard against storing nothing.
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {"Wgs_1.3.yaml": _test_yaml("1.3")})
        assert ok is False
        assert message == (
            REFUSED + f"{FOLDER}/Wgs_1.3.yaml: Profile validation failed for 'Wgs_1.3.yaml': "
            "Field 'Version' must be three whole numbers joined by dots, each at most 9 digits, "
            "like 1.0.0: '1.3'. Synced 1 application profiles.")
        assert _stored(ctx) == STORED_BEFORE

    def test_a_sync_with_no_refused_file_replaces_them(self, fresh_app, monkeypatch):
        # Removing a file on purpose is not a refusal.
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {
            "Wgs_1.1.yaml": _test_yaml("1.1.0"), "Rna.yaml": _test_yaml("1.0.0", "RNA")})
        assert ok, message
        assert _stored(ctx) == [("RNA", "1.0.0", "Rna.yaml"), ("WGS", "1.1.0", "Wgs_1.1.yaml")]

    def test_a_sync_left_with_no_test_profiles_stops(self, fresh_app, monkeypatch):
        # The guard against replacing stored profiles with nothing still runs.
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message
        ok, message, _logged = _sync_tests(ctx, monkeypatch, {})
        assert not ok
        assert "Refusing to replace" in message
        assert _stored(ctx) == STORED_BEFORE
