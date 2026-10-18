"""A synced kit file that gives one key twice is refused, not read.

``IndexKitSyncParser`` read kit YAML with ``safe_load_strict``, which keeps
the last of two keys without a word: a file listing one index name twice
stored the second sequence under that name and lost the first. The upload
path has refused that since ``ec465fc``; the sync did not.

The sync's own machinery then keeps the stored kit and names the file on the
config-sync page (``_fetch_index_kits`` / ``_synced_kits_to_keep`` in
``services/github_sync.py``), so this only has to make the parser refuse
and say why.
"""

import pytest

from seqsetup.services.index_kit_sync_parser import IndexKitSyncParser

GOOD = """\
name: Synced kit
version: "1.0"
index_mode: single
i7_indexes:
  - name: A1
    sequence: ATTACTCG
  - name: A2
    sequence: TCCGGAGA
"""

REPEATED_KEY = """\
name: Synced kit
version: "1.0"
index_mode: single
i7_indexes:
  - name: A1
    sequence: ATTACTCG
    sequence: TCCGGAGA
"""

REPEATED_TOP_KEY = """\
name: Synced kit
name: Other kit
version: "1.0"
index_mode: single
i7_indexes:
  - name: A1
    sequence: ATTACTCG
"""


class TestARepeatedKeyIsRefused:

    @pytest.mark.parametrize("content, key, line", [
        (REPEATED_KEY, "sequence", 7),
        (REPEATED_TOP_KEY, "name", 2),
    ])
    def test_the_parser_raises_naming_the_key_and_its_line(self, content, key, line):
        with pytest.raises(ValueError) as refused:
            IndexKitSyncParser.parse(content, "kit.yaml")

        message = str(refused.value)
        assert key in message and f"line {line}" in message, message

    def test_a_file_with_no_repeated_key_is_read(self):
        kit = IndexKitSyncParser.parse(GOOD, "kit.yaml")

        assert [i.name for i in kit.i7_indexes] == ["A1", "A2"]

    def test_a_file_that_is_not_yaml_still_comes_back_as_none(self):
        assert IndexKitSyncParser.parse("name: [unclosed\n", "kit.yaml") is None


SINGLE_WITH_I5 = """\
name: Synced kit
version: "1.0"
index_mode: single
i7_indexes:
  - name: A1
    sequence: ATTACTCG
i5_indexes:
  - name: A1
    sequence: TATAGCCT
"""

COMBINATORIAL_WITH_PAIRS = """\
name: Synced kit
version: "1.0"
index_mode: combinatorial
i7_indexes:
  - name: A1
    sequence: ATTACTCG
i5_indexes:
  - name: B1
    sequence: TATAGCCT
index_pairs:
  - name: P1
    index1:
      name: A1
      sequence: ATTACTCG
"""

DUAL_WITH_LISTS = """\
name: Synced kit
version: "1.0"
index_mode: unique_dual
index_pairs:
  - name: P1
    index1:
      name: A1
      sequence: ATTACTCG
    index2:
      name: A1
      sequence: TATAGCCT
i7_indexes:
  - name: Z9
    sequence: CGCTCATT
"""


class TestAListTheModeDoesNotReadIsRefused:
    """``_parse_kit`` reads ``index_pairs`` for unique_dual and the two lists
    for the other modes, so the lists a mode does not read went nowhere: a
    file saying ``index_mode: single`` with an ``i5_indexes`` list synced as
    an i7-only kit and the sync reported success. The upload path has refused
    that since this branch; the sync is the path with no human on it."""

    @pytest.mark.parametrize("content, unread", [
        (SINGLE_WITH_I5, "i5_indexes"),
        (COMBINATORIAL_WITH_PAIRS, "index_pairs"),
        (DUAL_WITH_LISTS, "i7_indexes"),
    ])
    def test_the_unread_key_is_named(self, content, unread):
        with pytest.raises(ValueError) as refused:
            IndexKitSyncParser.parse(content, "kit.yaml")

        message = str(refused.value)
        assert unread in message, message
        assert "index_mode" in message, message

    def test_a_file_whose_lists_match_its_mode_is_read(self):
        kit = IndexKitSyncParser.parse(GOOD, "kit.yaml")

        assert [i.name for i in kit.i7_indexes] == ["A1", "A2"]
