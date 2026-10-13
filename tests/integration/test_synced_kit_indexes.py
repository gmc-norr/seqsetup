"""A config sync stores a kit file's indexes exactly as the file writes them,
and stores nothing from a kit file the index check refuses.

Before this, the only thing any test asked of a synced kit was how many kits
came back and their names, so the sequences a sample is demultiplexed by could
have been dropped or swapped without a test going red.
"""

from seqsetup.models.index import IndexMode
from seqsetup.services.github_sync import GitHubSyncError

GOOD_KIT_YAML = """\
name: "Dual Kit"
version: "2.1.0"
index_mode: unique_dual
index_pairs:
  - name: "D701-D501"
    well_position: "A01"
    index1:
      name: "D701"
      sequence: "ATTACTCG"
    index2:
      name: "D501"
      sequence: "TATAGCCT"
  - name: "D702-D502"
    well_position: "B01"
    index1:
      name: "D702"
      sequence: "TCCGGAGA"
    index2:
      name: "D502"
      sequence: "ATAGAGGC"
"""

# Parses fine; the index check refuses it on its version.
REFUSED_KIT_YAML = """\
name: "Refused Kit"
version: "spring-2026"
index_mode: unique_dual
index_pairs:
  - name: "R01"
    index1:
      name: "R-i7"
      sequence: "CGCTCATT"
    index2:
      name: "R-i5"
      sequence: "GTACTGAC"
"""


def _sync_with_kits(ctx, monkeypatch, kit_files: dict):
    """One real config sync with index kits on, only the GitHub fetches
    replaced: the profile folders hold one good profile and its test profile,
    and the index-kit folder holds ``kit_files`` (name -> text)."""
    from .test_sheet_followups import TEST_PROFILE_YAML, _app_profile_yaml
    config = ctx.profile_sync_config_repo.get()
    config.github_repo_url = "https://github.com/example/config"
    config.sync_instruments_enabled = False
    config.sync_index_kits_enabled = True
    ctx.profile_sync_config_repo.save(config)
    folders = {
        config.application_profiles_path.strip("/"): {
            "KitProfile.yaml": _app_profile_yaml("KitProfile", '"4.3.6"')},
        config.test_profiles_path.strip("/"): {"Wgs.yaml": TEST_PROFILE_YAML},
        config.index_kits_path.strip("/"): kit_files,
    }
    texts = {}

    def listing(owner, repo, branch, path):
        path = path.strip("/")
        if path not in folders:
            raise GitHubSyncError(f"GitHub API error: 404 Not Found ({path})")
        entries = []
        for name, value in folders[path].items():
            item_path = f"{path}/{name}"
            url = f"https://raw.githubusercontent.com/example/config/main/{item_path}"
            texts[url] = value
            entries.append({"type": "file", "name": name, "path": item_path,
                            "download_url": url})
        return entries

    service = ctx.get_github_sync_service()
    monkeypatch.setattr(service, "_fetch_directory_contents", listing)
    monkeypatch.setattr(service, "_fetch_file_content", lambda url: texts[url])
    # mongomock's bulk_write does not take pymongo's ReplaceOne; save the kits
    # one by one, through the same per-kit save the repository itself calls.
    monkeypatch.setattr(ctx.index_kit_repo, "bulk_save",
                        lambda kits: [ctx.index_kit_repo.save(kit) for kit in kits])
    return service.sync()


def _pairs(kit):
    return [(pair.name, pair.well_position,
             pair.index1.name, pair.index1.sequence,
             pair.index2.name, pair.index2.sequence)
            for pair in kit.index_pairs]


class TestASyncedKitHoldsTheFilesIndexes:
    def test_the_stored_kit_has_the_files_pairs_names_and_sequences(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _count = _sync_with_kits(
            ctx, monkeypatch, {"dual.yaml": GOOD_KIT_YAML})

        assert (ok, "1 index kits" in message) == (True, True)
        (kit,) = ctx.index_kit_repo.list_synced()
        assert (kit.name, kit.version, kit.index_mode) == (
            "Dual Kit", "2.1.0", IndexMode.UNIQUE_DUAL)
        assert _pairs(kit) == [
            ("D701-D501", "A01", "D701", "ATTACTCG", "D501", "TATAGCCT"),
            ("D702-D502", "B01", "D702", "TCCGGAGA", "D502", "ATAGAGGC"),
        ]

    def test_a_kit_file_the_index_check_refuses_is_not_stored(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _count = _sync_with_kits(
            ctx, monkeypatch,
            {"dual.yaml": GOOD_KIT_YAML, "refused.yaml": REFUSED_KIT_YAML})

        assert (ok, "1 index kits" in message) == (True, True)
        assert [kit.name for kit in ctx.index_kit_repo.list_synced()] == ["Dual Kit"]
