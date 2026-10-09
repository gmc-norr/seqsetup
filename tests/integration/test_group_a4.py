"""Group A4: test versions (spec 2026-10-07 group A4), through the app."""

import html

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


class TestAPasteCarriesVersions:
    """Paste and file: the test_version column and the "Version for rows
    without one" box (spec §2)."""

    def _post(self, client, run_id, action, text, default_test="", default_version=None):
        from .test_paste_preview import ORIGIN
        data = {"paste_data": text, "lanes": ["1"], "default_test_id": default_test}
        if default_version is not None:
            data["default_test_version"] = default_version
        return client.post(f"/runs/{run_id}/samples/{action}", data=data, headers=ORIGIN)

    def _versions(self, ctx, run_id):
        return {s.sample_id: (s.test_id, s.test_version)
                for s in ctx.run_repo.get_by_id(run_id).samples}

    def test_the_column_and_the_box(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = self._post(logged_in_client, run_id, "bulk",
                       "sample_id,test_id,test_version\nS1,WGS,1.2\nS2,WGS,\nS3,,\n",
                       default_test="WGS", default_version="1")
        assert r.status_code == 200
        assert self._versions(ctx, run_id) == {
            "S1": ("WGS", "1.2"), "S2": ("WGS", "1"), "S3": ("WGS", "1")}

    def test_without_the_box_a_row_keeps_no_version(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        self._post(logged_in_client, run_id, "bulk", "S1,WGS\n")
        assert self._versions(ctx, run_id) == {"S1": ("WGS", "")}

    def test_a_row_with_a_version_and_no_test_is_refused(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = self._post(logged_in_client, run_id, "bulk",
                       "sample_id,test_id,test_version\nS1,WGS,1\nS2,,2\nS3,,1\n")
        assert r.status_code == 200
        assert ("Bulk import rejected: Row(s) 3, 4: a test version needs a test. Give the row "
                "a test, or pick one in Test for rows without one.") in html.unescape(r.text)
        assert self._versions(ctx, run_id) == {}

    def test_a_picked_test_lets_a_row_keep_its_version(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        self._post(logged_in_client, run_id, "bulk", "sample_id,test_version\nS1,2\n",
                   default_test="WGS")
        assert self._versions(ctx, run_id) == {"S1": ("WGS", "2")}

    def test_a_picked_test_without_a_version_is_refused(self, logged_in_client, fresh_app):
        # A test and its version are set together (decision 6; plan review of 562b2e2).
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = self._post(logged_in_client, run_id, "bulk",
                       "sample_id,test_id,test_version\nS1,WGS,1\nS2,,\nS3,,2\nS4,,\n",
                       default_test="WGS")
        assert r.status_code == 200
        assert ("Bulk import rejected: Row(s) 3, 5: the picked test needs a version. Fill in "
                "Version for rows without one, for example 1.") in html.unescape(r.text)
        assert self._versions(ctx, run_id) == {}

    def test_the_preview_offers_no_add_for_a_picked_test_without_a_version(self, logged_in_client,
                                                                            fresh_app):
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = self._post(logged_in_client, run_id, "preview", "S1\n", default_test="WGS")
        page = html.unescape(r.text)
        assert "The picked test needs a version." in page
        assert ("Row(s) 1: the picked test needs a version. Fill in Version for rows without one, "
                "for example 1.") in page
        assert '<button type="button" class="btn btn-primary" disabled>Add samples</button>' in page

    @pytest.mark.parametrize("text,default_test", [
        ("sample_id,test_version\nS1,\nS3,2\n", "WGS"),  # S1 takes the picked test, no version
        ("sample_id,test_id,test_version\nS1,,5\nS3,WGS,2\n", ""),  # S1 has a version, no test
    ])
    def test_a_row_already_in_the_run_does_not_stop_the_add(self, logged_in_client, fresh_app,
                                                             text, default_test):
        # It is skipped, never added (plan review of 8b17009).
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        self._post(logged_in_client, run_id, "bulk", "S1,WGS\n", default_version="1")
        preview = self._post(logged_in_client, run_id, "preview", text, default_test=default_test)
        assert "Add 1 sample</button>" in preview.text
        r = self._post(logged_in_client, run_id, "bulk", text, default_test=default_test)
        assert r.status_code == 200
        assert "Bulk import rejected" not in r.text
        assert self._versions(ctx, run_id) == {"S1": ("WGS", "1"), "S3": ("WGS", "2")}

    @pytest.mark.parametrize("text,default_test", [
        ("S1\n", "WGS"),  # the picked test, no version
        ("sample_id,test_version\nS1,2\n", ""),  # a version, no test
    ])
    def test_the_hint_names_the_rows_above(self, logged_in_client, fresh_app, text, default_test):
        # Those rows are Look (yellow), not red (plan review of 8b17009).
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = self._post(logged_in_client, run_id, "preview", text, default_test=default_test)
        assert '<span class="paste-blocked-hint">Fix the rows named above first.</span>' in r.text
        assert "Fix the red rows first." not in r.text

    def test_the_box_gives_no_version_to_a_row_without_a_test(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        self._post(logged_in_client, run_id, "bulk", "S1,WGS\nS2\n", default_version="1")
        assert self._versions(ctx, run_id) == {"S1": ("WGS", "1"), "S2": ("", "")}

    def test_the_preview_offers_no_add_for_a_version_without_a_test(self, logged_in_client,
                                                                     fresh_app):
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = self._post(logged_in_client, run_id, "preview", "sample_id,test_version\nS1,2\n")
        page = html.unescape(r.text)
        assert "A test version needs a test." in page
        assert ("Row(s) 2: a test version needs a test. Give the row a test, or pick one in "
                "Test for rows without one.") in page
        assert '<button type="button" class="btn btn-primary" disabled>Add samples</button>' in page

    @pytest.mark.parametrize("action", ["bulk", "preview"])
    @pytest.mark.parametrize("value", ["v1", "1" + "0" * 300])
    def test_a_bad_box_is_a_400(self, logged_in_client, fresh_app, action, value):
        from seqsetup.models.sample import TEST_VERSION_RULE
        from .test_paste_preview import _run
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = self._post(logged_in_client, run_id, action, "S1,WGS\n", default_version=value)
        assert r.status_code == 400
        assert r.text == f"Version for rows without one: {TEST_VERSION_RULE}."
        assert self._versions(ctx, run_id) == {}

    def test_a_bad_cell_adds_nothing(self, logged_in_client, fresh_app):
        from seqsetup.models.sample import TEST_VERSION_RULE
        from .test_paste_preview import _run
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = self._post(logged_in_client, run_id, "bulk", "sample_id,test_version\nS1,1\nS2,v1\n")
        assert r.status_code == 200
        assert (f"Bulk import rejected: Row(s) 3: the test version is not right. "
                f"{TEST_VERSION_RULE}.") in html.unescape(r.text)
        assert self._versions(ctx, run_id) == {}

    def test_the_preview_shows_it_and_sends_the_box_back(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run, _wgs
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = self._post(logged_in_client, run_id, "preview",
                       "sample_id,test_id,test_version\nS1,WGS,1.2\nS2,WGS,\n",
                       default_version="1")
        assert r.status_code == 200
        page = html.unescape(r.text)
        assert "<th scope=\"col\">Version</th>" in page
        assert "Version for blank rows: <b>1</b>" in page
        assert '<input type="hidden" name="default_test_version" value="1">' in page
        assert "<i>1</i> <span class=\"paste-picked\">(picked)</span>" in page

    def test_the_form_has_the_box(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert 'name="default_test_version"' in page
        assert "Version for rows without one" in page


def _sample(sid, test="", version=""):
    from seqsetup.models.sample import Sample
    return Sample(id=f"id-{sid}", sample_id=sid, test_id=test, test_version=version, lanes=[1])


def _tests(ctx, *pairs):
    # Imported here: a module-level TestProfile would be collected by pytest.
    from seqsetup.models.test_profile import TestProfile
    for test, version in pairs:
        ctx.test_profile_repo.save(TestProfile(test_type=test, test_name=test, version=version,
                                               source_file=f"{test}_{version}.yaml"))


def _tests_of(ctx, run_id):
    return {s.sample_id: (s.test_id, s.test_version)
            for s in ctx.run_repo.get_by_id(run_id).samples}


def _set_test(client, run_id, ids, test, version=None, only_if=None):
    import json
    from .test_paste_preview import ORIGIN
    data = {"sample_ids": json.dumps([f"id-{i}" for i in ids]), "test_id": test}
    if version is not None:
        data["test_version"] = version
    if only_if is not None:
        data["only_if"] = only_if
    return client.post(f"/runs/{run_id}/samples/set-test-id", data=data, headers=ORIGIN)


class TestSetTestSetsBoth:
    """POST .../samples/set-test-id sets a test and its version together
    (spec §2, decision 6)."""

    def _run(self, ctx):
        from .test_paste_preview import _run
        return _run(ctx, samples=[_sample("S1", "RNA", "2"), _sample("S2")])

    def test_both(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        r = _set_test(logged_in_client, run_id, ["S1", "S2"], "WGS", " 1.2 ")
        assert r.status_code == 200
        assert _tests_of(ctx, run_id) == {"S1": ("WGS", "1.2"), "S2": ("WGS", "1.2")}
        (event,) = ctx.audit_event_repo.search(limit=5, event_prefix="sample.bulk_test_id_set")
        assert (event.details["test_id"], event.details["test_version"]) == ("WGS", "1.2")

    def test_both_empty_clears_both(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        r = _set_test(logged_in_client, run_id, ["S1"], "", "")
        assert r.status_code == 200
        assert _tests_of(ctx, run_id)["S1"] == ("", "")

    @pytest.mark.parametrize("test,version,message", [
        ("WGS", "", "Give the test version too, for example 1."),
        ("WGS", None, "Give the test version too, for example 1."),
        ("", "1", "Pick a test for this version."),
        ("WGS", "v1", "A test version is 1, 2 or 3 whole numbers joined by dots, each at most "
                      "9 digits, like 1, 1.2 or 1.2.3."),
        ("WGS", "1" + "0" * 300, "A test version is 1, 2 or 3 whole numbers joined by dots, "
                                 "each at most 9 digits, like 1, 1.2 or 1.2.3."),
    ])
    def test_refused_and_nothing_changes(self, logged_in_client, fresh_app, test, version, message):
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        r = _set_test(logged_in_client, run_id, ["S1"], test, version)
        assert (r.status_code, r.text) == (400, message)
        assert _tests_of(ctx, run_id) == {"S1": ("RNA", "2"), "S2": ("", "")}


class TestTheFixBoxes:
    """The run page's fix boxes: one for samples with no test (test and
    version), one per test for samples with a test but no version (spec §2)."""

    def _page(self, client, ctx):
        from .test_paste_preview import _run
        _tests(ctx, ("WGS", "1.0.0"), ("RNA", "2.0.0"))
        run_id = _run(ctx, samples=[_sample("S1"), _sample("S2", "WGS"), _sample("S3", "RNA"),
                                    _sample("S4", "WGS"), _sample("S5", "WGS", "1")])
        return run_id, html.unescape(client.get(f"/runs/{run_id}").text)

    def test_the_box_for_samples_without_a_test_asks_for_both(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run_id, page = self._page(logged_in_client, ctx)
        assert "Set test and version for the 1 sample without one:" in page
        assert """<input type="hidden" name="sample_ids" value='["id-S1"]'>""" in page

    def test_one_box_per_test_for_samples_without_a_version(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run_id, page = self._page(logged_in_client, ctx)
        assert "WGS: set the version for the 2 samples without one:" in page
        assert """<input type="hidden" name="sample_ids" value='["id-S2", "id-S4"]'>""" in page
        assert "RNA: set the version for the 1 sample without one:" in page
        assert """<input type="hidden" name="sample_ids" value='["id-S3"]'>""" in page
        assert '<input type="hidden" name="test_id" value="WGS">' in page

    def test_a_version_box_keeps_the_test(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id, _page = self._page(logged_in_client, ctx)
        r = _set_test(logged_in_client, run_id, ["S2", "S4"], "WGS", "1", only_if="no_version")
        assert r.status_code == 200
        assert _tests_of(ctx, run_id) == {
            "S1": ("", ""), "S2": ("WGS", "1"), "S3": ("RNA", ""), "S4": ("WGS", "1"),
            "S5": ("WGS", "1")}

    def test_each_box_says_what_it_fixes(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run_id, page = self._page(logged_in_client, ctx)
        assert page.count('<input type="hidden" name="only_if" value="no_test">') == 1
        assert page.count('<input type="hidden" name="only_if" value="no_version">') == 2


class TestAFixBoxFromAnOldPage:
    """A fix box loaded before someone else changed its samples saves
    nothing: 409, naming the samples (spec §2, review of plan 68fc2c0)."""

    STALE = "These samples changed since this page was loaded: {}. Reload the page and try again."

    def _run(self, ctx):
        from .test_paste_preview import _run
        _tests(ctx, ("WGS", "1.0.0"), ("RNA", "2.0.0"))
        return _run(ctx, samples=[_sample("S1"), _sample("S2", "WGS"), _sample("S4", "WGS")])

    def test_a_version_box_after_the_test_was_changed(self, logged_in_client, fresh_app):
        # Measured before this rule: S2 became WGS 1.
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        assert _set_test(logged_in_client, run_id, ["S2"], "RNA", "2").status_code == 200
        r = _set_test(logged_in_client, run_id, ["S2", "S4"], "WGS", "1", only_if="no_version")
        assert (r.status_code, r.text) == (409, self.STALE.format("S2"))
        assert _tests_of(ctx, run_id) == {"S1": ("", ""), "S2": ("RNA", "2"), "S4": ("WGS", "")}

    def test_a_version_box_after_the_test_was_cleared(self, logged_in_client, fresh_app):
        # Without a version, only the test tells: the box would give S2 a test.
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        assert _set_test(logged_in_client, run_id, ["S2"], "", "").status_code == 200
        r = _set_test(logged_in_client, run_id, ["S2", "S4"], "WGS", "1", only_if="no_version")
        assert (r.status_code, r.text) == (409, self.STALE.format("S2"))
        assert _tests_of(ctx, run_id) == {"S1": ("", ""), "S2": ("", ""), "S4": ("WGS", "")}

    def test_a_version_box_after_a_version_was_set(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        assert _set_test(logged_in_client, run_id, ["S4"], "WGS", "2").status_code == 200
        r = _set_test(logged_in_client, run_id, ["S2", "S4"], "WGS", "1", only_if="no_version")
        assert (r.status_code, r.text) == (409, self.STALE.format("S4"))
        assert _tests_of(ctx, run_id)["S2"] == ("WGS", "")

    def test_the_test_box_after_a_test_was_set(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        assert _set_test(logged_in_client, run_id, ["S1"], "RNA", "2").status_code == 200
        r = _set_test(logged_in_client, run_id, ["S1"], "WGS", "1", only_if="no_test")
        assert (r.status_code, r.text) == (409, self.STALE.format("S1"))
        assert _tests_of(ctx, run_id)["S1"] == ("RNA", "2")

    def test_the_test_box_on_a_page_that_is_up_to_date(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        r = _set_test(logged_in_client, run_id, ["S1"], "WGS", "1", only_if="no_test")
        assert r.status_code == 200
        assert _tests_of(ctx, run_id)["S1"] == ("WGS", "1")

    def test_a_sample_removed_since_is_not_a_change(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        run.samples = [s for s in run.samples if s.sample_id != "S4"]
        ctx.run_repo.save(run)
        r = _set_test(logged_in_client, run_id, ["S2", "S4"], "WGS", "1", only_if="no_version")
        assert r.status_code == 200
        assert _tests_of(ctx, run_id) == {"S1": ("", ""), "S2": ("WGS", "1")}

    def test_another_only_if_is_a_400(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._run(ctx)
        r = _set_test(logged_in_client, run_id, ["S2"], "WGS", "1", only_if="always")
        assert (r.status_code, r.text) == (400, "only_if must be no_test or no_version")
        assert _tests_of(ctx, run_id)["S2"] == ("WGS", "")

    def test_no_box_on_a_ready_run(self, logged_in_client, fresh_app):
        from seqsetup.models.sequencing_run import RunStatus
        from .test_paste_preview import _run
        _app, ctx, _db = fresh_app
        _tests(ctx, ("WGS", "1.0.0"))
        run_id = _run(ctx, samples=[_sample("S2", "WGS")], status=RunStatus.READY)
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert "set the version for the" not in page


class TestEachTestOnce:
    """Each test is offered once, with its synced versions (spec §2)."""

    def test_the_lists_and_the_hint(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run
        _app, ctx, _db = fresh_app
        _tests(ctx, ("WGS", "1.0.0"), ("WGS", "1.2.0"), ("RNA", "2.0.0"))
        run_id = _run(ctx, samples=[_sample("S1")])
        page = html.unescape(logged_in_client.get(f"/runs/{run_id}").text)
        bulk = page.split('id="bulk-test-id-input"', 1)[1].split("</select>", 1)[0]
        assert bulk.count('<option value="WGS">') == 1
        paste = page.split('id="default_test_id"', 1)[1].split("</select>", 1)[0]
        assert paste.count('<option value="WGS">') == 1
        fix = page.split('id="fix-test-id"', 1)[1].split("</select>", 1)[0]
        assert fix.count('<option value="WGS">') == 1
        assert page.count("Synced: RNA 2.0.0 · WGS 1.0.0, 1.2.0") == 3


class TestTheSampleTableShowsTheVersion:
    def test_the_test_cell(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, samples=[_sample("S1", "WGS", "1"), _sample("S2", "WGS")])
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert '<td title="WGS 1">WGS 1</td>' in page
        assert '<td title="WGS">WGS</td>' in page


class TestAddingOneSample:
    """POST /runs/{run_id}/samples takes a version, with the rules of Set test."""

    def _add(self, client, run_id, **fields):
        from .test_paste_preview import ORIGIN
        return client.post(f"/runs/{run_id}/samples", data={"sample_id": "S9", **fields},
                           headers=ORIGIN)

    def test_both(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = self._add(logged_in_client, run_id, test_id="WGS", test_version="1")
        assert r.status_code == 200
        assert _tests_of(ctx, run_id) == {"S9": ("WGS", "1")}
        (event,) = ctx.audit_event_repo.search(limit=5, event_prefix="sample.added")
        assert event.details["test_version"] == "1"

    def test_neither(self, logged_in_client, fresh_app):
        from .test_paste_preview import _run
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        assert self._add(logged_in_client, run_id).status_code == 200
        assert _tests_of(ctx, run_id) == {"S9": ("", "")}

    @pytest.mark.parametrize("fields,message", [
        ({"test_id": "WGS"}, "Give the test version too, for example 1."),
        ({"test_version": "1"}, "Pick a test for this version."),
        ({"test_id": "WGS", "test_version": "1.x"},
         "A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, "
         "like 1, 1.2 or 1.2.3."),
    ])
    def test_refused(self, logged_in_client, fresh_app, fields, message):
        from .test_paste_preview import _run
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = self._add(logged_in_client, run_id, **fields)
        assert (r.status_code, r.text) == (400, message)
        assert _tests_of(ctx, run_id) == {}


class TestALimsWorklistCarriesVersions:
    """The worklist import sets each sample's version; a bad one refuses the
    whole worklist (spec §2)."""

    def test_the_version_is_set(self, logged_in_client, fresh_app, monkeypatch):
        from .test_group_a1 import _import, _lims, _run, _stored
        _app, ctx, _db = fresh_app
        _run(ctx, [])
        _lims(ctx, monkeypatch, [
            {"sample_id": "P1", "test_id": "WGS", "test_version": "1.2"},
            {"sample_id": "P2", "test_id": "WGS", "test_version": 2},
            {"sample_id": "P3", "test_id": "WGS"},
        ])
        resp = _import(logged_in_client)
        assert resp.status_code == 200
        assert {s.sample_id: s.test_version for s in _stored(ctx).samples} == {
            "P1": "1.2", "P2": "2", "P3": ""}

    def test_a_bad_version_adds_nothing(self, logged_in_client, fresh_app, monkeypatch):
        from .test_group_a1 import _import, _lims, _run, _stored
        _app, ctx, _db = fresh_app
        _run(ctx, [])
        _lims(ctx, monkeypatch, [
            {"sample_id": "P1", "test_id": "WGS", "test_version": "1"},
            {"sample_id": "P2", "test_id": "WGS", "test_version": 1.1},
        ])
        before = _stored(ctx).to_dict()
        resp = _import(logged_in_client)
        assert resp.status_code == 200
        assert ("Worklist import rejected: Sample 'P2' has a test version that is a number "
                "with a decimal point (1.1)") in html.unescape(resp.text)
        assert _stored(ctx).to_dict() == before

    def test_a_version_without_a_test_adds_nothing(self, logged_in_client, fresh_app,
                                                   monkeypatch):
        # Measured before this rule: P1 was stored with version 1 and no test.
        from .test_group_a1 import _import, _lims, _run, _stored
        _app, ctx, _db = fresh_app
        _run(ctx, [])
        _lims(ctx, monkeypatch, [{"sample_id": "P1", "test_version": "1"}])
        before = _stored(ctx).to_dict()
        resp = _import(logged_in_client)
        assert resp.status_code == 200
        assert ("Worklist import rejected: Sample 'P1' has a test version but no test."
                in html.unescape(resp.text))
        assert _stored(ctx).to_dict() == before

    def test_a_decimal_sample_id_adds_nothing(self, logged_in_client, fresh_app, monkeypatch):
        # Measured on e65c60d: 23.10 was stored as sample 23.1 (decision 12).
        from .test_group_a1 import _import, _lims, _run, _stored
        _app, ctx, _db = fresh_app
        _run(ctx, [])
        _lims(ctx, monkeypatch, [{"sample_id": "P1", "test_id": "WGS", "test_version": "1"},
                                 {"sample_id": 23.10, "test_id": "WGS", "test_version": "1"}])
        before = _stored(ctx).to_dict()
        resp = _import(logged_in_client)
        assert resp.status_code == 200
        assert ("Worklist import rejected: LIMS row 2 has a sample ID that is a number with a "
                "decimal point (23.1)") in html.unescape(resp.text)
        assert _stored(ctx).to_dict() == before


class TestTheAdminLimsPage:
    def test_the_test_version_field_box(self, logged_in_client, fresh_app):
        from .test_paste_preview import ORIGIN
        _app, ctx, _db = fresh_app
        page = logged_in_client.get("/admin/sample-api").text
        assert 'name="field_test_version"' in page
        assert "Test version field" in page
        resp = logged_in_client.post("/admin/settings/sample-api", data={
            "base_url": "https://lims.example.org/api", "field_test_version": "AssayVersion",
        }, headers=ORIGIN)
        assert resp.status_code == 200
        assert ctx.sample_api_config_repo.get().field_mappings == {"test_version": "AssayVersion"}
