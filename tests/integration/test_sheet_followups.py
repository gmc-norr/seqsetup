"""Sample Sheet follow-ups through the real routes and a real config sync
(spec 2026-09-29 Sample Sheet follow-ups)."""

import logging

from seqsetup.data import instruments as instruments_module
from seqsetup.models.instrument_definition import InstrumentDefinition, OnboardApplication
from seqsetup.services.validation import clear_validation_cache

from .conftest import disable_repos
from .test_sheet_safety import _assert_validation_passes, _seed_draft, _seed_synced_profile

ORIGIN = {"Origin": "http://testserver"}


class TestInvisibleCharacterStopsMarkReady:
    """A zero-width space in a sample's description keeps the run in Draft,
    with the message (spec §3)."""

    def test_zero_width_space_in_description_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "zw-desc")
        run = ctx.run_repo.get_by_id(run_id)
        run.samples[0].description = "Tube​7"
        ctx.run_repo.save(run)

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert "U+200B" in resp.text
        assert "If you cannot see it, delete the text and type it again." in resp.text
        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status.value == "draft"
        assert not stored.generated_samplesheet_v2


_SYNC_LOGGER = logging.getLogger("seqsetup.services.github_sync")

TEST_PROFILE_YAML = (
    "TestType: WGS\n"
    "TestName: WGS\n"
    "Description: Whole genome\n"
    'Version: "1.0.0"\n'
    "ApplicationProfiles:\n"
    "  - ApplicationProfileName: GuardProfile\n"
    '    ApplicationProfileVersion: "1.0.0"\n'
)


def _app_profile_yaml(name: str, software_version: str) -> str:
    """An application profile file. ``software_version`` is written as is:
    '"4.10"' is quoted, '4.10' is not."""
    return (
        f"ApplicationProfileName: {name}\n"
        'ApplicationProfileVersion: "1.0.0"\n'
        "ApplicationName: BCLConvert\n"
        "ApplicationType: BclConvert\n"
        "Settings:\n"
        f"  SoftwareVersion: {software_version}\n"
        "DataFields:\n"
        "  - Sample_ID\n"
    )


class _Messages(logging.Handler):
    """Collects what the sync logs (decision 9)."""

    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _sync(ctx, monkeypatch, app_profile_files: dict[str, str]):
    """Run one config sync with only the GitHub fetches replaced: the folder
    listing and the file text. The real parse, check and save run. The
    test-profile folder always holds TEST_PROFILE_YAML."""
    config = ctx.profile_sync_config_repo.get()
    config.github_repo_url = "https://github.com/example/config"
    config.sync_instruments_enabled = False
    config.sync_index_kits_enabled = False
    ctx.profile_sync_config_repo.save(config)
    folders = {
        config.application_profiles_path.strip("/"): app_profile_files,
        config.test_profiles_path.strip("/"): {"Wgs.yaml": TEST_PROFILE_YAML},
    }
    texts = {}

    def listing(owner, repo, branch, path):
        path = path.strip("/")
        entries = []
        for name, text in folders[path].items():
            url = f"https://raw.githubusercontent.com/example/config/main/{path}/{name}"
            texts[url] = text
            entries.append({"type": "file", "name": name, "path": f"{path}/{name}", "download_url": url})
        return entries

    service = ctx.get_github_sync_service()
    monkeypatch.setattr(service, "_fetch_directory_contents", listing)
    monkeypatch.setattr(service, "_fetch_file_content", lambda url: texts[url])
    return service.sync()


class TestSyncRefusesRiskyValues:
    """Through a real config sync (spec 2026-09-29 Sample Sheet follow-ups, §1)."""

    def test_unquoted_4_10_is_skipped_and_logged(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        handler = _Messages()
        _SYNC_LOGGER.addHandler(handler)
        try:
            ok, message, _count = _sync(ctx, monkeypatch, {
                "Good.yaml": _app_profile_yaml("Good", '"4.3.6"'),
                "Bad.yaml": _app_profile_yaml("Bad", "4.10"),
            })
        finally:
            _SYNC_LOGGER.removeHandler(handler)

        assert ok, message
        assert [p.name for p in ctx.app_profile_repo.list_all()] == ["Good"]
        assert any(
            "Bad.yaml" in m and "'SoftwareVersion' is a number with a decimal point" in m
            for m in handler.messages
        ), handler.messages

    def test_quoted_4_10_is_stored_and_written_as_typed(
        self, fresh_app, logged_in_client, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        try:
            ok, message, _count = _sync(ctx, monkeypatch, {
                "GuardProfile.yaml": _app_profile_yaml("GuardProfile", '"4.10"'),
            })
            assert ok, message
            (profile,) = ctx.app_profile_repo.list_all()
            assert profile.settings["SoftwareVersion"] == "4.10"

            # Astra plan review P2: follow it into the Sample Sheet. The
            # instrument must offer BCLConvert 4.10, or Mark Ready refuses the
            # version.
            ctx.instrument_definition_repo.save(InstrumentDefinition(
                name="NovaSeq X Series",
                samplesheet_name="NovaSeqXSeries",
                version="1.0.0",
                chemistry_type="2-color",
                onboard_applications=[OnboardApplication(name="BCLConvert", software_version="4.10")],
            ))
            instruments_module.clear_synced_instruments_cache()
            clear_validation_cache()
            run_id = _seed_draft(ctx, "quoted-4-10", test_id="WGS")
            _assert_validation_passes(ctx, run_id)

            resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

            assert resp.status_code == 200, resp.text[:400]
            lines = ctx.run_repo.get_by_id(run_id).generated_samplesheet_v2.split("\n")
            assert "SoftwareVersion,4.10" in lines
            assert "SoftwareVersion,4.1" not in lines
        finally:
            instruments_module.clear_synced_instruments_cache()
            clear_validation_cache()


class TestSyncIntoStoredProfiles:
    """A refused file when profiles are already stored (Astra review P7): the
    sync replaces them with the ones that passed, unless none passed; then it
    stops and keeps the old ones."""

    def test_a_refused_profile_is_gone_and_blocks_mark_ready(
        self, fresh_app, logged_in_client, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        good = _app_profile_yaml("Good", '"4.3.6"')
        first = _sync(ctx, monkeypatch, {
            "Good.yaml": good, "GuardProfile.yaml": _app_profile_yaml("GuardProfile", '"4.3.6"'),
        })
        assert first[0], first[1]

        ok, message, _count = _sync(ctx, monkeypatch, {
            "Good.yaml": good, "GuardProfile.yaml": _app_profile_yaml("GuardProfile", "4.10"),
        })

        assert ok, message
        assert [p.name for p in ctx.app_profile_repo.list_all()] == ["Good"]
        run_id = _seed_draft(ctx, "sync-gone", test_id="WGS")
        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)
        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert "GuardProfile" in resp.text and "not found" in resp.text
        assert ctx.run_repo.get_by_id(run_id).status.value == "draft"

    def test_when_every_profile_is_refused_the_old_ones_stay(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        first = _sync(ctx, monkeypatch, {
            "GuardProfile.yaml": _app_profile_yaml("GuardProfile", '"4.3.6"'),
        })
        assert first[0], first[1]

        ok, message, _count = _sync(ctx, monkeypatch, {
            "GuardProfile.yaml": _app_profile_yaml("GuardProfile", "4.10"),
        })

        assert not ok
        assert "Refusing to replace 1 existing application profiles with 0 fetched items" in message
        (profile,) = ctx.app_profile_repo.list_all()
        assert profile.settings["SoftwareVersion"] == "4.3.6"


class TestStoredProfileMismatchStopsMarkReady:
    """A stored profile whose Settings say BarcodeMismatchesIndex1: 3 (written
    straight into the database, past the sync check) stops Mark Ready at the
    writer; the run stays Draft (spec §1)."""

    def test_a_setting_of_3_stops_mark_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        try:
            _seed_synced_profile(ctx, "GuardApp", settings={
                "SoftwareVersion": "4.3.6", "BarcodeMismatchesIndex1": 3,
            })
            run_id = _seed_draft(ctx, "mm-profile", test_id="GUARD_T")
            _assert_validation_passes(ctx, run_id)

            resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

            assert resp.status_code == 500
            assert "Failed to generate exports" in resp.text
            run = ctx.run_repo.get_by_id(run_id)
            assert run.status.value == "draft"
            assert run.generated_samplesheet_v2 is None
        finally:
            instruments_module.clear_synced_instruments_cache()
            clear_validation_cache()
