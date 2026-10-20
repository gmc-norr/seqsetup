"""A config sync measures every item it is about to store before it deletes
anything (outside review of 51eb3c4, P2-1).

The sync replaces what it stored before: it deletes, then writes. MongoDB
refuses a record over 16 MiB, and a kit file under the sync's 10 MiB download
cap can be one -- each pair's stored id repeats the kit's name -- so the write
failed after the delete, and the synced kits were gone. Each kit, profile and
instrument is now measured where it is built, beside its other checks; one too
large is a refused file, so nothing it would replace is deleted.

The tests lower the limit between the sizes of real items: a file near 8 MiB
is too slow to read in a test.
"""

import itertools

from bson import BSON

from seqsetup.input_rules.instruments import check_synced_instrument_file, definitions_from
from seqsetup.input_rules.kits import build_kit
from seqsetup.input_rules.profiles import build_application_profile, check_application_profile_file
from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.services import github_sync
from seqsetup.services.index_kit_sync_parser import IndexKitSyncParser

from .test_group_a2 import GOOD_FILES
from .test_group_a4 import _sync_tests, _test_yaml
from .test_sheet_followups import _app_profile_yaml
from .test_synced_kit_indexes import GOOD_KIT_YAML, GOOD_LAB_KIT, _sync_with_kits, _synced


def _size(item) -> int:
    return len(BSON.encode(item.to_dict()))


def _kit(text):
    return build_kit(IndexKitSyncParser.check(text, "k.yaml").value,
                     created_by="github_sync", source="github")


def _sequences(count):
    """``count`` distinct 8-base sequences."""
    return ["".join(bases) for bases in itertools.islice(itertools.product("ACGT", repeat=8),
                                                         0, count * 37, 37)]


I7S, I5S = _sequences(40), list(reversed(_sequences(40)))
BIG_LAB_KIT = 'name: "Lab Kit"\nversion: "2.0"\nindex_mode: unique_dual\nindex_pairs:\n' + "".join(
    f'  - name: "L{n:02}"\n    index1:\n      name: "L{n:02}-i7"\n      sequence: "{i7}"\n'
    f'    index2:\n      name: "L{n:02}-i5"\n      sequence: "{i5}"\n'
    for n, (i7, i5) in enumerate(zip(I7S, I5S)))
GUARD = _app_profile_yaml("GuardProfile", '"4.3.6"')
BIG_PROFILE = _app_profile_yaml("BigProfile", '"4.3.6"').replace(
    '  SoftwareVersion: "4.3.6"\n',
    '  SoftwareVersion: "4.3.6"\n' + "".join(f"  Extra{n}: value{n}\n" for n in range(80)))
TESTS = {"Wgs.yaml": _test_yaml("1.0.0")}


class TestTheLimitIsMongoDBs:

    def test_it_is_16_mib_less_the_export_files_margin(self):
        assert github_sync._MOST_STORED_BYTES == 16 * 1024 * 1024 - 64 * 1024

    def test_a_kit_file_under_the_download_cap_can_be_too_large_to_store(self):
        """The reviewer's case, measured 2026-10-20: 20,000 pairs with
        110-character names in a kit with a 250-character name -- an 8.07 MiB
        file, which the rules and IndexValidator accept -- is a 17.2 MiB
        record."""
        name = "K" * 250
        pairs = [IndexPair(id=f"{name}_{n:06d}{'P' * 104}", name=f"{n:06d}{'P' * 104}",
                           index1=Index(name=f"{n:06d}{'P' * 104}", sequence="ACGTACGTAC",
                                        index_type=IndexType.I7),
                           index2=Index(name=f"{n:06d}{'P' * 104}", sequence="TGCATGCATG",
                                        index_type=IndexType.I5))
                 for n in range(20000)]
        kit = IndexKit(name=name, version="1.0.0", index_mode=IndexMode.UNIQUE_DUAL,
                       index_pairs=pairs)

        assert _size(kit) > github_sync._MOST_STORED_BYTES
        assert f"would take {_size(kit):,} bytes" in github_sync._too_large_to_store(kit)

    def test_a_kit_of_ordinary_size_is_stored(self):
        assert github_sync._too_large_to_store(_kit(GOOD_KIT_YAML)) == ""

    def test_a_record_one_byte_over_shows_two_different_sizes(self, monkeypatch):
        """In MiB to two places both were 15.94 (fresh review of the P2
        fixes, P3-5)."""
        kit = _kit(GOOD_KIT_YAML)
        monkeypatch.setattr(github_sync, "_MOST_STORED_BYTES", _size(kit) - 1)

        said = github_sync._too_large_to_store(kit)

        assert f"would take {_size(kit):,} bytes" in said, said
        assert f"over the {_size(kit) - 1:,} bytes" in said, said


class TestAKitTooLargeToStoreIsRefused:

    def test_the_file_is_named_and_the_stored_kits_stay(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": GOOD_LAB_KIT,
                                                                 "dual.yaml": GOOD_KIT_YAML})
        assert ok, message
        small, big = _size(_kit(GOOD_KIT_YAML)), _size(_kit(BIG_LAB_KIT))
        assert small < big
        monkeypatch.setattr(github_sync, "_MOST_STORED_BYTES", (small + big) // 2)

        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": BIG_LAB_KIT,
                                                                 "dual.yaml": GOOD_KIT_YAML})

        assert ok is False
        assert "index_kits/lab.yaml (Lab Kit 2.0)" in message and "MiB" in message, message
        assert _synced(ctx) == ["Dual Kit 2.1.0", "Lab Kit 1.0"]
        assert "Kept the stored index kits Lab Kit 1.0 until the file is fixed." in message

    def test_a_file_too_large_still_gives_its_kit_name_and_version(self, fresh_app, monkeypatch):
        """Two files that give one name and version are both refused: the
        one too large to store named the kit, and the other was stored
        (fresh review of the P2 fixes, P2-2)."""
        _app, ctx, _db = fresh_app
        same_name = BIG_LAB_KIT.replace('version: "2.0"', 'version: "1.0"')
        small, big = _size(_kit(GOOD_LAB_KIT)), _size(_kit(same_name))
        monkeypatch.setattr(github_sync, "_MOST_STORED_BYTES", (small + big) // 2)

        ok, message, _count = _sync_with_kits(ctx, monkeypatch, {
            "dual.yaml": GOOD_KIT_YAML, "a.yaml": GOOD_LAB_KIT, "b.yaml": same_name})

        assert ok is False
        assert ("index_kits/a.yaml (Lab Kit 1.0): index_kits/b.yaml gives this kit "
                "name and version too; a kit name and version may be in one file only") in message
        assert "index_kits/b.yaml (Lab Kit 1.0): would take" in message, message
        assert _synced(ctx) == ["Dual Kit 2.1.0"]


class TestAProfileTooLargeToStoreIsRefused:

    def test_the_file_is_named_and_the_stored_profiles_stay(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS, {"Guard.yaml": GUARD})
        assert ok, message
        small = _size(build_application_profile(
            check_application_profile_file(GUARD, "g.yaml").value, "g.yaml"))
        big = _size(build_application_profile(
            check_application_profile_file(BIG_PROFILE, "b.yaml").value, "b.yaml"))
        assert small < big
        monkeypatch.setattr(github_sync, "_MOST_STORED_BYTES", (small + big) // 2)

        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS,
                                           {"Guard.yaml": GUARD, "Big.yaml": BIG_PROFILE})

        assert ok is False
        assert "profiles/application_profiles/Big.yaml: would take" in message, message
        assert sorted(p.name for p in ctx.app_profile_repo.list_all()) == ["GuardProfile"]


class TestAnInstrumentTooLargeToStoreIsRefused:

    def test_the_file_is_named_and_the_stored_instruments_stay(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS, {"Guard.yaml": GUARD},
                                           instrument_files=GOOD_FILES)
        assert ok, message
        assert ctx.instrument_definition_repo.collection.count_documents({}) == 2
        profile = _size(build_application_profile(
            check_application_profile_file(GUARD, "g.yaml").value, "g.yaml"))
        instruments = [_size(definition) for name, text in GOOD_FILES.items()
                       for definition in definitions_from(
                           check_synced_instrument_file(text, name).value, name)]
        # The limit goes between the profiles and the instruments.
        assert profile * 2 < min(instruments)
        monkeypatch.setattr(github_sync, "_MOST_STORED_BYTES", profile * 2)

        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS, {"Guard.yaml": GUARD},
                                           instrument_files=GOOD_FILES)

        assert ok is False
        assert "Instrument files were refused" in message and "would take" in message, message
        assert ctx.instrument_definition_repo.collection.count_documents({}) == 2
