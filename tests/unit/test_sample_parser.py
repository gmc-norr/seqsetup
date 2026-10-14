"""Tests for the sample paste/upload parser.

The parser is a clinical-sample entry point: misparsing a row shifts every
downstream column, so a sample ID can silently get paired with the wrong
test_id and indexes. Tests focus on the failure modes that produce silent
sample-identity errors.
"""

import pytest

from seqsetup.services import sample_parser as sample_parser_module
from seqsetup.services.sample_parser import parse_pasted_samples, read_pasted_samples


class TestSampleCountCap:
    """The parser must refuse a paste with more rows than the per-run cap,
    rather than building millions of objects and deferring the failure."""

    def test_exceeding_cap_raises(self, monkeypatch):
        monkeypatch.setattr(sample_parser_module, "MAX_SAMPLES_PER_RUN", 5)
        data = "sample_id,test_id,index,index2\n" + "\n".join(
            f"S{i},WGS,ATTACTCG,TATAGCCT" for i in range(6))
        with pytest.raises(ValueError, match="maximum"):
            parse_pasted_samples(data)

    def test_at_cap_succeeds(self, monkeypatch):
        monkeypatch.setattr(sample_parser_module, "MAX_SAMPLES_PER_RUN", 5)
        data = "sample_id,test_id,index,index2\n" + "\n".join(
            f"S{i},WGS,ATTACTCG,TATAGCCT" for i in range(5))
        samples = parse_pasted_samples(data)
        assert len(samples) == 5


class TestParseBasicShape:
    """Regression coverage — current valid inputs must continue to parse."""

    def test_tab_separated_with_header(self):
        data = "Sample_ID\tTest_ID\tIndex_I7\tIndex_I5\n"
        data += "S1\tWGS\tATTACTCG\tTATAGCCT\n"
        data += "S2\tRNA\tTCCGGAGA\tATAGAGGC\n"
        result = parse_pasted_samples(data)
        assert len(result) == 2
        assert result[0].sample_id == "S1"
        assert result[0].test_id == "WGS"
        assert result[0].index1_sequence == "ATTACTCG"
        assert result[0].index2_sequence == "TATAGCCT"
        assert result[1].sample_id == "S2"

    def test_comma_separated_with_header(self):
        data = "Sample_ID,Test_ID,Index_I7,Index_I5\n"
        data += "S1,WGS,ATTACTCG,TATAGCCT\n"
        result = parse_pasted_samples(data)
        assert len(result) == 1
        assert result[0].sample_id == "S1"
        assert result[0].index1_sequence == "ATTACTCG"

    def test_no_header_default_column_order(self):
        """Without a header row: sample ID, then test, and nothing more
        (index mix-up audit, 2026-10-14)."""
        data = "S1\tWGS\n"
        result = parse_pasted_samples(data)
        assert len(result) == 1
        assert result[0].sample_id == "S1"
        assert result[0].test_id == "WGS"

    def test_dna_lowercased_is_uppercased(self):
        data = "sample_id\ttest_id\tindex\tindex2\nS1\tWGS\tattactcg\ttatagcct\n"
        result = parse_pasted_samples(data)
        assert result[0].index1_sequence == "ATTACTCG"
        assert result[0].index2_sequence == "TATAGCCT"

    def test_invalid_dna_raises(self):
        data = "sample_id\ttest_id\tindex\tindex2\nS1\tWGS\tATTACTCXZ\tTATAGCCT\n"
        with pytest.raises(ValueError, match="Invalid characters"):
            parse_pasted_samples(data)

    def test_blank_input_returns_empty(self):
        assert parse_pasted_samples("") == []
        assert parse_pasted_samples("\n\n\n") == []


class TestParseSampleMixUpClassBugs:
    """The clinically dangerous cases: a row that misparses changes which
    test_id / indexes a sample gets paired with."""

    def test_quoted_comma_in_sample_id_kept_as_single_field(self):
        """Excel/Numbers paste of a sample ID containing a comma must not split the row."""
        data = 'Sample_ID,Test_ID,Index_I7,Index_I5\n'
        data += '"Patient, S1",WGS,ATTACTCG,TATAGCCT\n'
        result = parse_pasted_samples(data)
        assert len(result) == 1
        assert result[0].sample_id == "Patient, S1"
        assert result[0].test_id == "WGS"  # would be "S1" if split incorrectly
        assert result[0].index1_sequence == "ATTACTCG"
        assert result[0].index2_sequence == "TATAGCCT"

    def test_quoted_field_with_embedded_quotes(self):
        """RFC 4180 double-quote escape inside a quoted field."""
        data = 'Sample_ID,Test_ID,Index_I7,Index_I5\n'
        data += '"Patient ""A""",WGS,ATTACTCG,TATAGCCT\n'
        result = parse_pasted_samples(data)
        assert len(result) == 1
        assert result[0].sample_id == 'Patient "A"'


class TestRejectBrokenQuoting:
    """A stray double quote must reject the paste, naming the line — not merge
    the following rows into one cell (whose samples then silently vanish) or
    quietly rewrite a sample ID ('"S2"x' -> 'S2x')."""

    def test_unclosed_quote_rejects_instead_of_swallowing_rows(self):
        data = 'S1\tWGS\n"S2\tWGS\nS3\tWGS\nS4\tWGS'
        with pytest.raises(ValueError, match=r'Line 2: .*quote'):
            parse_pasted_samples(data)

    def test_text_after_closing_quote_rejects(self):
        data = 'S1,WGS\n"S2"x,WGS\nS3,WGS\n'
        with pytest.raises(ValueError, match=r'Line 2: .*quote'):
            parse_pasted_samples(data)

    def test_quoted_cell_spanning_lines_rejects(self):
        # Quote closed two lines later: valid CSV, but it merges S2 and S3.
        data = 'S1\tWGS\n"S2\tWGS\nS3"\tWGS\nS4\tWGS\n'
        with pytest.raises(ValueError, match=r'Line 2: .*quote'):
            parse_pasted_samples(data)

    def test_error_names_first_line_after_header(self):
        data = 'Sample_ID,Test_ID\nS1,WGS\nS2,WGS\n"S3,WGS\nS4,WGS\n'
        with pytest.raises(ValueError, match=r'Line 4: '):
            parse_pasted_samples(data)

    def test_line_break_inside_cell_is_named_in_error(self):
        # An Excel cell with Alt+Enter looks the same as a stray quote closed
        # on a later line; both are refused, and the message says so.
        data = 'S1,WGS,"note\nline2"\nS2,WGS,x\n'
        with pytest.raises(ValueError, match=r"Line 1: .*more than one line"):
            parse_pasted_samples(data)


class TestLineEndings:
    """Old-Mac (CR-only) line endings used to crash the parser with an
    unhandled csv.Error; they are ordinary line breaks."""

    def test_cr_only_line_endings_parse(self):
        result = parse_pasted_samples("S1,WGS\rS2,WGS\r")
        assert [s.sample_id for s in result] == ["S1", "S2"]

    def test_crlf_line_endings_parse(self):
        result = parse_pasted_samples("S1\tWGS\r\nS2\tWGS\r\n")
        assert [s.sample_id for s in result] == ["S1", "S2"]


class TestRejectMissingSampleId:
    """A row with content but no sample_id is a data error — silent skip
    would route the dropped sample's reads to the Undetermined bucket."""

    def test_row_with_index_but_no_sample_id_rejects(self):
        data = "Sample_ID,Index_I7,Index_I5\n"
        data += "S1,ATTACTCG,TATAGCCT\n"
        data += ",ATTACTCG,TATAGCCT\n"  # missing sample_id
        with pytest.raises(ValueError, match="sample_id is required"):
            parse_pasted_samples(data)

    def test_error_message_names_the_row_number(self):
        data = "Sample_ID,Index_I7,Index_I5\n"  # header = line 1
        data += "S1,ATTACTCG,TATAGCCT\n"        # line 2 (valid)
        data += ",ATTACTCG,TATAGCCT\n"          # line 3 (bad)
        data += ",ATTACTCG,TATAGCCT\n"          # line 4 (bad)
        with pytest.raises(ValueError) as excinfo:
            parse_pasted_samples(data)
        # 1-based, includes the header line. Lines 3 and 4 should be named.
        assert "3" in str(excinfo.value)
        assert "4" in str(excinfo.value)

    def test_wholly_blank_rows_still_skipped(self):
        """A blank line is intentional (trailing newline, paragraph break) —
        only rows with ACTUAL content but missing sample_id are an error."""
        data = "Sample_ID,Index_I7,Index_I5\n"
        data += "S1,ATTACTCG,TATAGCCT\n"
        data += "\n\n"  # blank lines — should be silently dropped
        result = parse_pasted_samples(data)
        assert len(result) == 1


class TestBomStripping:
    """Excel and many LIMS exports prepend a UTF-8 BOM; without stripping
    it the first header cell becomes "﻿sample_id" and breaks the
    header mapping — column order silently shifts."""

    def test_bom_prefix_stripped_when_header_present(self):
        data = "﻿Sample_ID,Test_ID,Index_I7,Index_I5\n"
        data += "S1,WGS,ATTACTCG,TATAGCCT\n"
        result = parse_pasted_samples(data)
        assert len(result) == 1
        assert result[0].sample_id == "S1"
        assert result[0].test_id == "WGS"
        assert result[0].index1_sequence == "ATTACTCG"

    def test_bom_prefix_does_not_break_non_default_column_order(self):
        """Regression: a BOM in front of a non-default column order would,
        without the strip, fall back to default mapping (sample_id=col0,
        test_id=col1, index1=col2, index2=col3) — feeding the test_id
        column's values into sample_id, etc."""
        # Columns: sample_id, index_i7, index_i5, test_id (NOT default order)
        data = "﻿Sample_ID,Index_I7,Index_I5,Test_ID\n"
        data += "S1,ATTACTCG,TATAGCCT,WGS\n"
        result = parse_pasted_samples(data)
        assert result[0].sample_id == "S1"
        assert result[0].index1_sequence == "ATTACTCG"
        assert result[0].test_id == "WGS"


class TestReadPastedSamples:
    """read_pasted_samples reports how it read the paste, so the preview can
    show guesses and dropped columns instead of hiding them."""

    def test_rows_carry_their_source_line(self):
        read = read_pasted_samples("sample_id,test_id\n\nS1,WGS\nS2,WGS\n")
        assert [(s.sample_id, s.line) for s in read.samples] == [("S1", 3), ("S2", 4)]

    def test_header_columns_used_and_unused(self):
        read = read_pasted_samples("sample_id\ttest_id\twell\nS1\tWGS\tA03\n")
        assert read.header_found is True
        assert read.columns_used == [("sample_id", "Sample ID"), ("test_id", "Test")]
        assert read.columns_unused == ["well"]

    def test_empty_unknown_column_is_not_listed(self):
        assert read_pasted_samples("sample_id\tcomment\nS1\t\n").columns_unused == []

    def test_headerless_columns_are_guessed_by_position(self):
        read = read_pasted_samples("S1\tATTACTCG\n")
        assert read.header_found is False
        assert read.columns_used == [("column 1", "Sample ID"), ("column 2", "Test")]
        assert read.samples[0].test_id == "ATTACTCG"  # the guess the preview must show

    def test_headerless_extra_columns_are_refused(self):
        """Index mix-up audit, 2026-10-14: no column is read by guess past the test."""
        with pytest.raises(ValueError, match="has no header row"):
            read_pasted_samples("S1,WGS,ATTACTCG,TATAGCCT,extra\n")

    def test_data_beyond_the_header_is_unused(self):
        assert read_pasted_samples("sample_id,test_id\nS1,WGS,surprise\n").columns_unused == ["column 3"]

    def test_parse_pasted_samples_still_returns_the_list(self):
        assert [s.sample_id for s in parse_pasted_samples("S1\nS2")] == ["S1", "S2"]

    def test_blank_input(self):
        read = read_pasted_samples("   ")
        assert (read.samples, read.header_found, read.columns_used, read.columns_unused) == ([], False, [], [])


class TestSampleIdColumnRanking:
    """A paste with more than one sample-ID-ish column: the real Sample ID
    column wins, however far right it sits. Taking the leftmost one stored a
    patient name as the Sample ID and dropped the lab's own ID."""

    def test_sample_id_beats_sample_name_on_its_left(self):
        read = read_pasted_samples(
            "Sample_Name\tSample_ID\tIndex\tIndex2\nJSmith\tLAB-001\tACGTACGT\tTTGGCCAA\n")
        assert read.samples[0].sample_id == "LAB-001"
        assert ("Sample_ID", "Sample ID") in read.columns_used
        assert read.columns_unused == ["Sample_Name"]

    def test_exact_sample_id_beats_sample(self):
        read = read_pasted_samples("Sample\tSample_ID\nJSmith\tLAB-001\n")
        assert read.samples[0].sample_id == "LAB-001"

    def test_exact_sample_id_beats_id(self):
        read = read_pasted_samples("ID\tsample id\n7\tLAB-001\n")
        assert read.samples[0].sample_id == "LAB-001"

    def test_sample_beats_name(self):
        read = read_pasted_samples("Name\tSample\nJSmith\tLAB-001\n")
        assert read.samples[0].sample_id == "LAB-001"

    def test_id_beats_sample_name(self):
        read = read_pasted_samples("Sample_Name\tID\nJSmith\tLAB-001\n")
        assert read.samples[0].sample_id == "LAB-001"

    def test_only_sample_name_is_still_the_sample_id(self):
        read = read_pasted_samples("Sample_Name\tTest_ID\nJSmith\tWGS\n")
        assert read.samples[0].sample_id == "JSmith"
        assert read.columns_used == [("Sample_Name", "Sample ID"), ("Test_ID", "Test")]

    def test_two_columns_of_the_same_rank_take_the_leftmost(self):
        assert read_pasted_samples("ID\tSample\n7\tLAB-001\n").samples[0].sample_id == "7"
        assert read_pasted_samples("Sample\tID\nLAB-001\t7\n").samples[0].sample_id == "LAB-001"

    def test_the_losing_column_is_not_read_as_another_field(self):
        read = read_pasted_samples("Name\tSample_ID\tTest_ID\nJSmith\tLAB-001\tWGS\n")
        assert read.samples[0].sample_id == "LAB-001"
        assert read.samples[0].test_id == "WGS"
        assert read.columns_unused == ["Name"]
