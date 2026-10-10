"""A paste's test version column (spec 2026-10-07 group A4, §2): read only
under a header that names it, checked as read, before any cut, and a bad
cell refuses the whole paste."""

import pytest

from seqsetup.models.sample import TEST_VERSION_RULE
from seqsetup.services.paste_preview import LOOK, OK, SKIPPED, build_paste_preview
from seqsetup.services.sample_parser import read_pasted_samples


def _versions(text: str) -> dict[str, str]:
    return {s.sample_id: s.test_version for s in read_pasted_samples(text).samples}


class TestTheColumn:
    @pytest.mark.parametrize("header", ["test_version", "TestVersion", "test version", "Test-Version"])
    def test_its_names(self, header):
        assert _versions(f"sample_id\ttest_id\t{header}\nS1\tWGS\t1.2\n") == {"S1": "1.2"}

    def test_it_marks_a_header_row_on_its_own(self):
        assert _versions("lab_no\ttest_version\nS1\t1\n") == {"S1": "1"}

    def test_a_column_named_only_version_is_not_read(self):
        read = read_pasted_samples("sample_id\ttest_id\tversion\nS1\tWGS\t1.2\n")
        assert [s.test_version for s in read.samples] == [""]
        assert read.columns_unused == ["version"]

    def test_without_a_header_a_fifth_column_is_not_read(self):
        read = read_pasted_samples("S1\tWGS\tACGTACGT\tTTGGCCAA\t1.2\n")
        assert [s.test_version for s in read.samples] == [""]
        assert read.columns_unused == ["column 5"]

    def test_the_columns_used_line_names_it(self):
        read = read_pasted_samples("sample_id\ttest_id\ttest_version\nS1\tWGS\t1\n")
        assert ("test_version", "Test version") in read.columns_used

    def test_spaces_around_are_stripped_and_an_empty_cell_is_no_version(self):
        assert _versions("sample_id,test_version\nS1, 1.2 \nS2,\n") == {"S1": "1.2", "S2": ""}


class TestABadCell:
    def test_it_refuses_the_whole_paste_naming_the_rows(self):
        with pytest.raises(ValueError) as caught:
            read_pasted_samples("sample_id,test_version\nS1,1\nS2,v1\nS3,1.x\n")
        assert str(caught.value) == (
            f"Row(s) 3, 4: the test version is not right. {TEST_VERSION_RULE}.")

    def test_a_long_cell_is_refused_not_cut(self):
        # Cut to 256 like the other cells, this cell would pass the rule
        # (review of 311d730); it is checked as read.
        cell = "1" + "0" * 300 + "v"
        with pytest.raises(ValueError, match=r"Row\(s\) 2: the test version is not right"):
            read_pasted_samples(f"sample_id,test_version\nS1,{cell}\n")

    def test_a_row_without_a_sample_id_is_reported_as_that(self):
        with pytest.raises(ValueError, match=r"Row\(s\) 2: sample_id is required"):
            read_pasted_samples("sample_id,test_version\n,v1\n")


class TestThePreview:
    def _row(self, text, default_version="", test_types=frozenset({"WGS"}), default_test=""):
        preview = build_paste_preview(
            read_pasted_samples(text), existing_ids=set(), test_types=set(test_types),
            default_test=default_test, default_version=default_version, room=100,
        )
        (row,) = preview.rows
        return row

    def test_it_shows_the_version(self):
        row = self._row("sample_id,test_id,test_version\nS1,WGS,1.2\n")
        assert (row.test_version, row.version_picked, row.state) == ("1.2", False, OK)

    def test_a_picked_version_is_marked(self):
        row = self._row("sample_id,test_id\nS1,WGS\n", default_version="1")
        assert (row.test_version, row.version_picked, row.state) == ("1", True, OK)

    def test_a_test_without_a_version_is_noted(self):
        row = self._row("sample_id,test_id\nS1,WGS\n")
        assert row.state == LOOK
        assert row.notes == ["No test version. Check will ask for one."]

    def test_no_test_gets_only_the_test_note(self):
        row = self._row("sample_id\nS1\n")
        assert row.notes == ["No test. Check will ask for one."]

    def test_without_test_profiles_there_is_no_note(self):
        row = self._row("sample_id,test_id\nS1,WGS\n", test_types=frozenset())
        assert (row.notes, row.state) == ([], OK)

    def test_a_version_without_a_test_stops_the_add(self):
        # A test and its version are set together (spec §2, decision 6).
        preview = build_paste_preview(
            read_pasted_samples("sample_id,test_id,test_version\nS1,WGS,1\nS2,,2\n"),
            existing_ids=set(), test_types={"WGS"}, default_test="", room=100,
        )
        row = preview.rows[1]
        assert (row.test_version, row.state, row.notes) == ("2", LOOK, ["A test version needs a test."])
        assert preview.versions_without_test == [3]
        assert not preview.can_add

    def test_a_picked_test_lets_the_version_through(self):
        row = self._row("sample_id,test_version\nS1,2\n", default_test="WGS")
        assert (row.test_id, row.test_version, row.state) == ("WGS", "2", OK)

    def test_a_picked_test_without_a_version_stops_the_add(self):
        # A test and its version are set together (spec §2, decision 6): a
        # row taking the picked test needs a version of its own or the box's.
        preview = build_paste_preview(
            read_pasted_samples("sample_id,test_id,test_version\nS1,WGS,\nS2,,2\nS3,,\n"),
            existing_ids=set(), test_types={"WGS"}, default_test="WGS", room=100,
        )
        own, versioned, picked = preview.rows
        assert (own.state, own.notes) == (LOOK, ["No test version. Check will ask for one."])
        assert (versioned.state, versioned.notes) == (OK, [])
        assert (picked.test_id, picked.test_version, picked.state, picked.notes) == (
            "WGS", "", LOOK, ["The picked test needs a version."])
        assert preview.picked_tests_without_version == [4]
        assert preview.picked_tests_without_version_text == (
            "Row(s) 4: the picked test needs a version. Fill in Version for rows without one, "
            "for example 1.")
        assert not preview.can_add

    def test_the_box_lets_a_picked_test_through(self):
        preview = build_paste_preview(
            read_pasted_samples("sample_id\nS1\n"), existing_ids=set(), test_types={"WGS"},
            default_test="WGS", default_version="1", room=100,
        )
        assert (preview.picked_tests_without_version, preview.can_add) == ([], True)

    @pytest.mark.parametrize("text,default_test", [
        ("sample_id,test_version\nS1,\nS2,1\n", "WGS"),  # S1 takes the picked test, no version
        ("sample_id,test_id,test_version\nS1,,2\nS2,WGS,1\n", ""),  # S1 has a version, no test
    ])
    def test_a_row_already_in_the_run_is_not_checked(self, text, default_test):
        # It is skipped, never added (plan review of 8b17009).
        preview = build_paste_preview(
            read_pasted_samples(text), existing_ids={"S1"}, test_types={"WGS"},
            default_test=default_test, room=100,
        )
        assert [(r.sample_id, r.state) for r in preview.rows] == [("S1", SKIPPED), ("S2", OK)]
        assert (preview.versions_without_test, preview.picked_tests_without_version) == ([], [])
        assert preview.can_add

    def test_the_box_gives_no_version_to_a_row_without_a_test(self):
        row = self._row("sample_id\nS1\n", default_version="1")
        assert (row.test_version, row.version_picked) == ("", False)
        assert row.notes == ["No test. Check will ask for one."]
