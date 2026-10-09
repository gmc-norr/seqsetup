"""The paste preview shows what a paste would add, before anything is saved.

It is read-only and decides nothing on its own: /samples/bulk re-reads the
same text and re-applies the blocking rule (a repeated ID).
"""

from seqsetup.services.paste_preview import build_paste_preview, repeated_sample_ids
from seqsetup.services.sample_parser import read_pasted_samples

HEADER = "sample_id\ttest_id\tindex_i7\tindex_i5\tindex_pair_name\n"


def _preview(text, *, existing=(), tests=("WGS",), default="", room=100, version="1"):
    # Every row gets a version from the box, so each test here sees only the
    # notes it is about; a test without a version gets its own note (spec
    # 2026-10-07 group A4): tests/unit/test_paste_test_version.py.
    return build_paste_preview(read_pasted_samples(text), set(existing), set(tests), default, room,
                               default_version=version)


class TestRowStates:
    """Each row is ok, look (can add), skipped (already in run) or blocked."""

    def test_clean_row_is_ok(self):
        row = _preview(HEADER + "S1\tWGS\tATTACTCG\tTATAGCCT\tUDP0001\n").rows[0]
        assert (row.state, row.notes, row.line) == ("ok", [], 2)
        assert (row.index1, row.index2, row.index_name) == ("ATTACTCG", "TATAGCCT", "UDP0001")

    def test_repeated_id_blocks_both_rows(self):
        p = _preview("S1,WGS\nS2,WGS\nS1,WGS\n")
        assert [r.state for r in p.rows] == ["blocked", "ok", "blocked"]
        assert p.rows[0].notes == ["Same ID as line 3."]
        assert p.repeated_ids == ["S1"]
        assert p.can_add is False

    def test_id_already_in_run_is_skipped(self):
        p = _preview("S1,WGS\nS2,WGS\n", existing={"S1"})
        assert p.rows[0].state == "skipped"
        assert (p.to_add, p.skipped, p.can_add) == (1, 1, True)

    def test_unknown_test_is_flagged(self):
        row = _preview("S1,WGX\n").rows[0]
        assert (row.state, row.notes) == ("look", ['No test called "WGX".'])

    def test_test_that_looks_like_dna_gets_a_hint(self):
        row = _preview("S1\tATTACTCG\tTATAGCCT\n").rows[0]
        assert "looks like an index sequence" in row.notes[0]

    def test_missing_test_is_flagged(self):
        assert _preview("S1\n").rows[0].notes == ["No test. Check will ask for one."]

    def test_no_test_checks_without_profiles(self):
        assert [r.state for r in _preview("S1\nS2,ANYTHING\n", tests=()).rows] == ["ok", "ok"]

    def test_index_name_without_sequence_is_flagged(self):
        row = _preview(HEADER + "S1\tWGS\t\t\tUDP0005\n").rows[0]
        assert row.notes == ["Index name but no sequences, so no index is set."]


class TestDefaultTest:
    """The picked test fills blank test cells only."""

    def test_fills_blank_tests_only(self):
        p = _preview("S1\nS2,RNA\n", tests=("WGS", "RNA"), default="WGS")
        assert [(r.test_id, r.test_picked) for r in p.rows] == [("WGS", True), ("RNA", False)]
        assert [r.state for r in p.rows] == ["ok", "ok"]


class TestSummary:
    """Counts, the guessed-columns flag and whether Add is allowed."""

    def test_guessed_only_when_headerless_with_several_columns(self):
        assert _preview("S1,WGS\n").guessed is True
        assert _preview("S1\n").guessed is False
        assert _preview("sample_id,test_id\nS1,WGS\n").guessed is False

    def test_counts(self):
        p = _preview("S1,WGS\nS2,WGX\nS3,WGS\n", existing={"S3"})
        assert (len(p.rows), p.to_add, p.to_look, p.skipped, p.blocked) == (3, 2, 1, 1, 0)

    def test_nothing_to_add_cannot_add(self):
        assert _preview("S1,WGS\n", existing={"S1"}).can_add is False

    def test_over_room_cannot_add(self):
        p = _preview("S1,WGS\nS2,WGS\n", room=1)
        assert (p.over_cap, p.can_add) == (True, False)


def test_repeated_sample_ids_keeps_first_seen_order():
    assert repeated_sample_ids(read_pasted_samples("B\nA\nB\nA\nC\n").samples) == ["B", "A"]
