"""A synced kit file that gives one key twice is refused, and the sync says so.

``IndexKitSyncParser`` read kit YAML with the loader that keeps the last of
two keys, so a file listing a key twice stored the second value and lost the
first with no word anywhere. It now refuses the file; the sync's own
machinery keeps the stored kit and names the file on the config-sync page.
"""

from .test_synced_kit_indexes import GOOD_KIT_YAML, _pairs, _sync_with_kits

# "D701" twice in one mapping: PyYAML would keep ATAGAGGC and lose ATTACTCG.
REPEATED_KEY_YAML = """\
name: "Dual Kit"
version: "2.1.0"
index_mode: unique_dual
index_pairs:
  - name: "D701-D501"
    index1:
      name: "D701"
      sequence: "ATTACTCG"
      sequence: "ATAGAGGC"
    index2:
      name: "D501"
      sequence: "TATAGCCT"
"""


class TestARepeatedKeyInASyncedKitFileIsRefused:

    def test_the_file_is_refused_and_named_with_its_reason(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _count = _sync_with_kits(
            ctx, monkeypatch, {"repeated.yaml": REPEATED_KEY_YAML})

        assert not ok, message
        assert "repeated.yaml" in message
        assert "sequence" in message and "line 9" in message, message
        assert ctx.index_kit_repo.list_synced() == []

    def test_the_stored_kit_stays_when_a_later_sync_repeats_a_key(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _count = _sync_with_kits(
            ctx, monkeypatch, {"dual.yaml": GOOD_KIT_YAML})
        assert ok, message
        before = _pairs(ctx.index_kit_repo.list_synced()[0])

        ok, message, _count = _sync_with_kits(
            ctx, monkeypatch, {"dual.yaml": REPEATED_KEY_YAML})

        assert not ok, message
        (kit,) = ctx.index_kit_repo.list_synced()
        assert _pairs(kit) == before

    def test_a_file_with_no_repeated_key_still_syncs(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app

        ok, message, _count = _sync_with_kits(
            ctx, monkeypatch, {"dual.yaml": GOOD_KIT_YAML})

        assert ok, message
        assert len(ctx.index_kit_repo.list_synced()) == 1
