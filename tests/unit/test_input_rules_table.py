"""The table reader behind the two kit CSV shapes
(docs/design/2026-10-18-input-rules-design.md, step 3).

A kit CSV's columns decide which sequence is the i7 and which the i5, so two
columns of one name are refused **before any row is read**: ``DictReader``
keeps only the last of them, so the other's sequences went nowhere. The kit
parser's own ``_columns_not_read`` refuses two *different* spellings of one
normal form (``index_2`` beside ``Index2``); two columns spelt the same way
were accepted.
"""

import pytest

from seqsetup.input_rules.table import (CellOverLines, ColumnGivenTwice, TableNotRead, column_key,
                                         read_table)


class TestEachRowKnowsItsLine:

    def test_a_row_carries_the_line_it_is_on(self):
        table = read_table("name,index\nA,ACGT\nB,TTTT\n")

        assert [(row.line, row.cells["name"]) for row in table.rows] == [(2, "A"), (3, "B")]

    def test_a_line_offset_names_the_file_s_own_line(self):
        table = read_table("name,index\nA,ACGT\n", line_offset=3)

        assert [row.line for row in table.rows] == [5]

    def test_a_cell_under_no_column_is_kept_apart(self):
        table = read_table("name,index\nA,ACGT,EXTRA\n")

        assert table.rows[0].extra == ["EXTRA"]


class TestAColumnNameGivenTwiceIsRefused:

    def test_two_columns_spelt_the_same_way(self):
        with pytest.raises(ColumnGivenTwice) as refused:
            read_table("name,index2,index2\nA,ACGT,TTTT\n")

        assert 'two columns named "index2"' in str(refused.value)
        assert refused.value.reason == "columns_not_read"

    def test_two_spellings_of_one_column_name(self):
        with pytest.raises(ColumnGivenTwice) as refused:
            read_table("name,index_2,Index2\nA,ACGT,TTTT\n")

        assert '"index_2"' in str(refused.value) and '"Index2"' in str(refused.value)

    def test_it_is_refused_before_a_row_is_read(self):
        """A row after the header must not be read at all: nothing is saved,
        and a huge file must not be walked first."""
        with pytest.raises(ColumnGivenTwice):
            read_table("name,index,index\n" + "A,ACGT,TTTT\n" * 5)

    def test_two_different_columns_are_read(self):
        table = read_table("name,index,index2\nA,ACGT,TTTT\n")

        assert table.header == ["name", "index", "index2"]

    def test_an_empty_header_name_is_not_a_repeat(self):
        table = read_table("name,,index\nA,x,ACGT\n")

        assert table.rows[0].cells["name"] == "A"


class TestTheNormalFormOfAColumnName:

    @pytest.mark.parametrize("written", ["index", "INDEX", "Index", " index ", "ind ex", "i_n_d_ex"])
    def test_spacing_and_case_and_underscores_do_not_matter(self, written):
        assert column_key(written) == "index"

    def test_two_names_that_differ_really_are_two(self):
        assert column_key("index") != column_key("index2")


class TestARowWhoseQuotesDoNotCloseIsRefused:
    """``csv`` read a broken quote as it could: ``P1,"ACGT"NNNN`` gave the
    sequence ACGTNNNN, and a quote never closed took the rest of the file
    into one cell. Read strictly, the file is refused naming the line
    (outside review of 51eb3c4, P2-2)."""

    @pytest.mark.parametrize("text, line", [
        ('name,index\nP1,"ACGT"NNNN\nP2,TCCGGAGA\n', 2),
        ('name,index\nP1,ACGTACGT\nP2,"TCCGGAGA\n', 3),
        ('"name,index\nP1,ACGTACGT\n', 1),
    ])
    def test_a_broken_quote_names_its_line(self, text, line):
        with pytest.raises(TableNotRead) as refused:
            read_table(text)

        assert refused.value.line == line
        assert f"Line {line}:" in str(refused.value)
        assert 'double quote (")' in str(refused.value)

    @pytest.mark.parametrize("text, line", [
        ('name,index\nP1,ACGTACGT\n\nP2,"TCCG"GAGA\n', 4),
        ('name,index\nP1,ACGTACGT\n\n\nP2,"TCCG"GAGA\n', 5),
        ('name,index\r\nP1,ACGTACGT\r\n\r\nP2,"TCCG"GAGA\r\n', 4),
        ('name,index\n\nP1,"TCCGGAGA\n', 3),
    ])
    def test_a_blank_line_before_the_row_is_not_the_row(self, text, line):
        """A blank line is skipped inside the read of the row after it, so
        the line taken before that read was the blank one (fresh review of
        the P2 fixes, P2-1)."""
        with pytest.raises(TableNotRead) as refused:
            read_table(text)

        assert refused.value.line == line

    @pytest.mark.parametrize("text, line", [
        ('name,index,index2,,\nA,ACGTACGT,TTGGCCAA,"\nB,GGGGCCCC,AACCGGTT\n"\nC,CATGCATG,GTACGTAC\n', 2),
        ('name,sequence,,\nA,ACGTACGT,"x\nB,GGGGCCCC\n"\nC,CATGCATG\n', 2),
    ])
    def test_a_cell_over_two_lines_under_a_second_blank_name_is_refused(self, text, line):
        """DictReader put the second blank column's None over the first
        one's cell, so the line break escaped the check and row B went into
        it without a word (second fresh review of the P2 fixes)."""
        with pytest.raises(CellOverLines) as refused:
            read_table(text)

        assert refused.value.line == line

    def test_a_cell_over_two_lines_after_a_blank_line_names_its_own_line(self):
        with pytest.raises(CellOverLines) as refused:
            read_table('name,index\nP1,ACGTACGT\n\n"P2\nX",TCCGGAGA\n')

        assert refused.value.line == 4

    def test_rows_after_blank_lines_keep_their_lines_and_cells(self):
        table = read_table('name,index,index2\n\nP1,ACGTACGT\n\n\nP2,TCCGGAGA,TATAGCCT,x\nP3\n')

        assert table.header == ["name", "index", "index2"]
        assert [(row.line, row.cells, row.extra) for row in table.rows] == [
            (3, {"name": "P1", "index": "ACGTACGT", "index2": None}, []),
            (6, {"name": "P2", "index": "TCCGGAGA", "index2": "TATAGCCT"}, ["x"]),
            (7, {"name": "P3", "index": None, "index2": None}, []),
        ]

    def test_a_cell_under_a_blank_column_name_is_under_no_column_name(self):
        table = read_table("name,,index, ,\nA,x,ACGTACGT,y,\nB\n")

        assert [(row.cells, row.extra) for row in table.rows] == [
            ({"name": "A", "index": "ACGTACGT"}, ["x", "y", ""]),
            ({"name": "B", "index": None}, []),
        ]

    def test_the_line_counts_the_lines_taken_off_the_front(self):
        with pytest.raises(TableNotRead) as refused:
            read_table('name,index\nP1,"ACGT"NNNN\n', line_offset=3)

        assert refused.value.line == 5

    def test_a_tsv_is_read_strictly_too(self):
        with pytest.raises(TableNotRead):
            read_table('Name\tSequence\nD701\t"ATTA"CTCG\n', delimiter="\t")

    def test_quotes_that_close_are_read(self):
        table = read_table('"name","index"\n"P1","ACGTACGT"\n"P2,x",TCCGGAGA\n')

        assert [(row.cells["name"], row.cells["index"]) for row in table.rows] == [
            ("P1", "ACGTACGT"), ("P2,x", "TCCGGAGA")]

    @pytest.mark.parametrize("text, line", [
        ('name,index\n"P1\nP2",ACGTACGT\nP3,TCCGGAGA\n', 2),
        ('name,index\nP1,ACGTACGT\n"P2\nP3,TCCGGAGA\nP4",CGCTCATT\n', 3),
        ('"na\nme",index\nP1,ACGTACGT\n', 1),
    ])
    def test_a_cell_over_two_lines_is_refused(self, text, line):
        """Rows merge into the cell, so the lines after it go nowhere -- the
        paste refuses the same (services/sample_parser.py)."""
        with pytest.raises(CellOverLines) as refused:
            read_table(text)

        assert refused.value.line == line
        assert f"Line {line}:" in str(refused.value) and "more than one line" in str(refused.value)
