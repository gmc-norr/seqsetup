"""A config sync stores a kit file's indexes exactly as the file writes them,
and stores nothing from a kit file the index check refuses.

Before this, the only thing any test asked of a synced kit was how many kits
came back and their names, so the sequences a sample is demultiplexed by could
have been dropped or swapped without a test going red.
"""

import pytest

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
        """A dict value is a sub-folder; None is a sub-folder that cannot
        be listed."""
        path = path.strip("/")
        if path not in folders or folders[path] is None:
            raise GitHubSyncError(f"GitHub API error: 403 Forbidden ({path})")
        entries = []
        for name, value in folders[path].items():
            item_path = f"{path}/{name}"
            if value is None or isinstance(value, dict):
                folders[item_path] = value
                entries.append({"type": "dir", "name": name, "path": item_path})
                continue
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

        # The night run's Q3, answered 2026-10-13: the refusal is named, not
        # passed off as a clean sync (TestARefusedKitIsNamedAndTheOldOneKept).
        assert ok is False and "1 index kits" in message
        assert "index_kits/refused.yaml" in message
        assert [kit.name for kit in ctx.index_kit_repo.list_synced()] == ["Dual Kit"]


LAB_KIT_YAML = """\
name: "Lab Kit"
version: "1.0"
index_mode: unique_dual
default_index1_cycles: {cycles}
index_pairs:
  - name: "L01"
    index1:
      name: "L-i7"
      sequence: "CGCTCATT"
    index2:
      name: "L-i5"
      sequence: "GTACTGAC"
"""
GOOD_LAB_KIT = LAB_KIT_YAML.format(cycles=8)
# The same kit after an edit that breaks a rule: 12 i7 cycles for 8-base i7s.
BROKEN_LAB_KIT = LAB_KIT_YAML.format(cycles=12)


def _synced(ctx):
    return sorted(f"{kit.name} {kit.version}" for kit in ctx.index_kit_repo.list_synced())


class TestARefusedKitIsNamedAndTheOldOneKept:
    """The night run's Q3, answered 2026-10-13 ("keep old, say so"): a kit
    file the sync cannot store is named in the sync's message with why, the
    kit stored before from it stays until the file is fixed, and everything
    else still syncs. Before, the kit simply vanished from the index picker
    while the sync said it succeeded."""

    def test_the_refusal_names_the_file_and_why(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": BROKEN_LAB_KIT})

        assert ok is False
        assert "Index kit files were refused" in message
        assert "index_kits/lab.yaml (Lab Kit 1.0)" in message
        assert "i7 index cycles is 12" in message
        assert ctx.profile_sync_config_repo.get().last_sync_status == "error"

    def test_the_kit_stored_before_stays(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, _message, _count = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": GOOD_LAB_KIT,
                                                                  "dual.yaml": GOOD_KIT_YAML})
        assert ok and _synced(ctx) == ["Dual Kit 2.1.0", "Lab Kit 1.0"]

        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": BROKEN_LAB_KIT,
                                                                 "dual.yaml": GOOD_KIT_YAML})

        assert ok is False
        assert _synced(ctx) == ["Dual Kit 2.1.0", "Lab Kit 1.0"]
        (lab,) = [kit for kit in ctx.index_kit_repo.list_synced() if kit.name == "Lab Kit"]
        assert lab.default_index1_cycles == 8, "the stored kit, not the refused file's"
        assert "Kept the stored index kits Lab Kit 1.0 until the file is fixed." in message

    def test_only_the_refused_kit_is_kept(self, fresh_app, monkeypatch):
        """A kit whose file left the repository is still removed."""
        _app, ctx, _db = fresh_app
        _sync_with_kits(ctx, monkeypatch, {"lab.yaml": GOOD_LAB_KIT, "dual.yaml": GOOD_KIT_YAML})

        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": BROKEN_LAB_KIT})

        assert ok is False
        assert _synced(ctx) == ["Lab Kit 1.0"]
        assert "Dual Kit" not in message

    def test_every_file_refused_keeps_them_all_and_is_not_an_empty_fetch(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _sync_with_kits(ctx, monkeypatch, {"lab.yaml": GOOD_LAB_KIT})

        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": BROKEN_LAB_KIT})

        assert ok is False and "Refusing to replace" not in message
        assert _synced(ctx) == ["Lab Kit 1.0"]

    def test_an_unreadable_file_keeps_every_stored_kit_it_could_be(self, fresh_app, monkeypatch):
        """A file that cannot be read names no kit, so every stored kit this
        sync did not read stays, and the message lists them."""
        _app, ctx, _db = fresh_app
        _sync_with_kits(ctx, monkeypatch, {"lab.yaml": GOOD_LAB_KIT, "dual.yaml": GOOD_KIT_YAML})

        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": "name: [unclosed",
                                                                 "dual.yaml": GOOD_KIT_YAML})

        assert ok is False
        assert "index_kits/lab.yaml: could not be read as an index kit" in message
        assert _synced(ctx) == ["Dual Kit 2.1.0", "Lab Kit 1.0"]
        assert "Kept the stored index kits Lab Kit 1.0 until the file is fixed." in message

    def test_a_clean_sync_is_unchanged(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": GOOD_LAB_KIT})
        assert ok is True and message.startswith("Synced ") and "refused" not in message


class TestNoKitVanishesWithoutBeingNamed:
    """Review P2-1 and P3-3 (2026-10-13), the same promise as the night run's
    Q3: a kit sub-folder that cannot be listed, or a kit file whose name ends
    in capitals, used to drop its kits while the sync said it succeeded."""

    def test_a_sub_folder_that_cannot_be_listed_keeps_its_kits(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _sync_with_kits(ctx, monkeypatch, {"dual.yaml": GOOD_KIT_YAML, "lab": {"lab.yaml": GOOD_LAB_KIT}})
        assert _synced(ctx) == ["Dual Kit 2.1.0", "Lab Kit 1.0"]

        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"dual.yaml": GOOD_KIT_YAML, "lab": None})

        assert ok is False
        assert "index_kits/lab: could not be listed" in message
        assert _synced(ctx) == ["Dual Kit 2.1.0", "Lab Kit 1.0"]

    @pytest.mark.parametrize("name", ["lab.YAML", "lab.Yml"])
    def test_a_kit_file_ending_in_capitals_is_read(self, fresh_app, monkeypatch, name):
        _app, ctx, _db = fresh_app
        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {name: GOOD_LAB_KIT})
        assert ok is True, message
        assert _synced(ctx) == ["Lab Kit 1.0"]


class TestAnUploadedKitIsNotOverwritten:
    """Review P2-2 (2026-10-13): a kit file whose name and version are a kit
    uploaded through SeqSetup replaced the uploaded kit -- its index
    sequences too -- while the sync said it succeeded, though the guide
    promises uploaded kits are kept. It is refused and named instead."""

    def test_the_uploaded_kit_stays_and_the_file_is_named(self, fresh_app, monkeypatch):
        from seqsetup.models.index import Index, IndexKit, IndexPair, IndexType
        _app, ctx, _db = fresh_app
        ctx.index_kit_repo.save(IndexKit(
            name="Dual Kit", version="2.1.0", index_mode=IndexMode.UNIQUE_DUAL, source="user",
            index_pairs=[IndexPair(id="u1", name="U1",
                                   index1=Index(name="u-i7", sequence="ATTACTCG", index_type=IndexType.I7),
                                   index2=Index(name="u-i5", sequence="GGGGGGGG", index_type=IndexType.I5))]))

        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"dual.yaml": GOOD_KIT_YAML,
                                                                 "lab.yaml": GOOD_LAB_KIT})

        assert ok is False
        assert ("index_kits/dual.yaml (Dual Kit 2.1.0): a kit of this name and version was "
                "uploaded through SeqSetup, and the uploaded one is kept") in message
        (kit,) = [k for k in ctx.index_kit_repo.list_all() if k.name == "Dual Kit"]
        assert kit.source == "user" and kit.index_pairs[0].index2.sequence == "GGGGGGGG"
        assert _synced(ctx) == ["Lab Kit 1.0"]
