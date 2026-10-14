"""A paste never guesses which column holds an index (index mix-up audit,
2026-10-14; the user's choice "Refuse, say why").

Without a header row the paste read columns 3 and 4 as the i7 and the i5 by
position: a paste in the order sample, test, i5, i7 stored them swapped, and
sample, i7, i5 stored the i7 as the test and the i5 as the i7. A header
column such as "Index 2" or "i7_sequence" was ignored, so the sample was
added without that index. Now a paste without a header row may hold only a
sample ID and a test, and a header column that looks like an index or a lane
but is not one SeqSetup reads refuses the whole paste, naming it.
"""

import pytest

from seqsetup.services.sample_parser import parse_pasted_samples

I7, I5 = "ATTACTCG", "TATAGCCT"
NEEDS_A_HEADER = "has no header row"
NOT_READ = "SeqSetup does not read"


class TestWithoutAHeaderOnlyTheIdAndTheTestAreRead:

    def test_four_columns_are_refused(self):
        """sample, test, i5, i7 used to store the i5 as the i7."""
        with pytest.raises(ValueError, match=NEEDS_A_HEADER):
            parse_pasted_samples(f"P1\tWGS\t{I5}\t{I7}\n")

    def test_three_columns_are_refused(self):
        """sample, i7, i5 used to store the i7 as the test."""
        with pytest.raises(ValueError, match=NEEDS_A_HEADER):
            parse_pasted_samples(f"P1\t{I7}\t{I5}\n")

    def test_a_third_column_on_a_later_row_is_refused_naming_it(self):
        with pytest.raises(ValueError, match=r"Row\(s\) 3: .*has no header row"):
            parse_pasted_samples(f"P1\tWGS\nP2\tWGS\nP3\tWGS\t{I7}\n")

    def test_the_message_says_what_to_do(self):
        with pytest.raises(ValueError, match=(
                r"Add a header row naming the columns, for example: "
                r"sample_id, test_id, index_i7, index_i5\.")):
            parse_pasted_samples(f"P1,WGS,{I7},{I5}\n")

    def test_a_list_of_ids_is_still_read(self):
        assert [s.sample_id for s in parse_pasted_samples("P1\nP2\n")] == ["P1", "P2"]

    def test_an_id_and_a_test_are_still_read(self):
        [sample] = parse_pasted_samples("P1\tWGS\n")
        assert (sample.sample_id, sample.test_id) == ("P1", "WGS")

    def test_the_same_columns_with_a_header_are_read(self):
        [sample] = parse_pasted_samples(f"sample_id\ttest_id\tindex_i5\tindex_i7\nP1\tWGS\t{I5}\t{I7}\n")
        assert (sample.index1_sequence, sample.index2_sequence) == (I7, I5)


class TestAColumnThatLooksLikeAnIndexOrALaneMustBeOneThatIsRead:

    @pytest.mark.parametrize("name", [
        "Index 2", "i7 index", "i7_sequence", "index1_sequence", "I5 Sequence", "Barcode",
        "Index2_Sequence", "i5seq",
    ])
    def test_an_unread_index_column_refuses_the_paste(self, name):
        with pytest.raises(ValueError, match=rf'Column\(s\) "{name}": {NOT_READ}'):
            parse_pasted_samples(f"sample_id\ttest_id\t{name}\nP1\tWGS\t{I7}\n")

    def test_a_second_i7_column_refuses_the_paste(self):
        with pytest.raises(ValueError, match=rf'Column\(s\) "i7": {NOT_READ}'):
            parse_pasted_samples(f"sample_id\tindex\ti7\nP1\t{I7}\t{I5}\n")

    def test_a_lane_column_refuses_the_paste_and_says_where_lanes_come_from(self):
        with pytest.raises(ValueError, match=r'Column\(s\) "Lane".*Lanes come from the Lanes picker'):
            parse_pasted_samples("sample_id\ttest_id\tLane\nP1\tWGS\t2\n")

    def test_the_message_lists_the_names_that_are_read(self):
        with pytest.raises(ValueError, match=(
                r"The i7 is read from a column named index, index1, i7, index_i7, i7_index "
                r"or index i7; the i5 from index2, i5, index_i5, i5_index or index i5\.")):
            parse_pasted_samples(f"sample_id\tIndex 2\nP1\t{I5}\n")

    def test_an_empty_unread_index_column_still_refuses(self):
        """The header alone says the file has an index there."""
        with pytest.raises(ValueError, match=NOT_READ):
            parse_pasted_samples("sample_id\ti7_sequence\nP1\t\n")

    @pytest.mark.parametrize("name", ["comment", "Well", "Plate", "Concentration", "Sample_Name"])
    def test_other_columns_are_still_left_unused(self, name):
        [sample] = parse_pasted_samples(f"sample_id\t{name}\nP1\tx\n")
        assert sample.sample_id == "P1"

    @pytest.mark.parametrize("i7_name, i5_name", [
        ("index", "index2"), ("index1", "i5"), ("i7", "index_i5"), ("index_i7", "i5_index"),
        ("i7_index", "index i5"), ("Index I7", "INDEX2"),
    ])
    def test_the_names_that_are_read_are_still_read(self, i7_name, i5_name):
        [sample] = parse_pasted_samples(f"sample_id\t{i7_name}\t{i5_name}\nP1\t{I7}\t{I5}\n")
        assert (sample.index1_sequence, sample.index2_sequence) == (I7, I5)

    @pytest.mark.parametrize("name", ["i7_name", "i5_name", "index_name", "index_pair_name", "index_kit"])
    def test_the_index_name_columns_that_are_read_are_fine(self, name):
        [sample] = parse_pasted_samples(f"sample_id\t{name}\nP1\tUDI0001\n")
        assert sample.sample_id == "P1"


class TestASampleIdHeaderIsFoundInAnyColumn:
    """A header row whose sample ID column is not the first was read as a
    sample, and every row's first cell (a well, say) as its sample ID."""

    def test_well_then_sample_id(self):
        samples = parse_pasted_samples("Well\tSample_ID\nA01\tPAT1\nB01\tPAT2\n")
        assert [s.sample_id for s in samples] == ["PAT1", "PAT2"]

    def test_a_first_cell_named_like_a_header_word_in_data_is_not_a_header(self):
        """A data row has no header word in any column."""
        assert [s.sample_id for s in parse_pasted_samples("A01\tPAT1\n")] == ["A01"]
