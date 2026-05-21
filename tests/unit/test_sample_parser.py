"""Tests for the sample paste/upload parser.

The parser is a clinical-sample entry point: misparsing a row shifts every
downstream column, so a sample ID can silently get paired with the wrong
test_id and indexes. Tests focus on the failure modes that produce silent
sample-identity errors.
"""

import pytest

from seqsetup.services.sample_parser import parse_pasted_samples


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
        data = "S1\tWGS\tATTACTCG\tTATAGCCT\n"
        result = parse_pasted_samples(data)
        assert len(result) == 1
        assert result[0].sample_id == "S1"
        assert result[0].test_id == "WGS"

    def test_dna_lowercased_is_uppercased(self):
        data = "S1\tWGS\tattactcg\ttatagcct\n"
        result = parse_pasted_samples(data)
        assert result[0].index1_sequence == "ATTACTCG"
        assert result[0].index2_sequence == "TATAGCCT"

    def test_invalid_dna_raises(self):
        data = "S1\tWGS\tATTACTCXZ\tTATAGCCT\n"
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
