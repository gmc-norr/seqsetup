"""Tests for index parser service."""

import pytest

from sequencing_run_setup.services.index_parser import IndexParser


class TestIndexParser:
    """Tests for IndexParser."""

    def test_parse_csv_simple(self):
        """Test parsing simple CSV format."""
        csv_content = """name,index,index2
Sample1,ATCGATCG,GCTAGCTA
Sample2,TTGGAATT,AACCGGTT"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        assert kit.name == "TestKit"
        assert len(kit.index_pairs) == 2
        assert kit.index_pairs[0].name == "Sample1"
        assert kit.index_pairs[0].index1.sequence == "ATCGATCG"
        assert kit.index_pairs[0].index2.sequence == "GCTAGCTA"

    def test_parse_csv_single_index(self):
        """Test parsing CSV with only i7 index (auto-detects single mode)."""
        csv_content = """name,index
Sample1,ATCGATCG
Sample2,TTGGAATT"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        # When no i5 indexes are present, auto-detects as single mode
        # and stores indexes in i7_indexes instead of index_pairs
        from sequencing_run_setup.models.index import IndexMode
        assert kit.index_mode == IndexMode.SINGLE
        assert len(kit.i7_indexes) == 2
        assert kit.i7_indexes[0].sequence == "ATCGATCG"
        assert kit.i7_indexes[0].name == "Sample1"

    def test_parse_csv_alternative_headers(self):
        """Test parsing CSV with alternative header names."""
        csv_content = """Sample_ID,Index,Index2
S1,ATCG,GCTA
S2,TTGG,AACC"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        assert len(kit.index_pairs) == 2
        assert kit.index_pairs[0].name == "S1"

    def test_parse_tsv_format(self):
        """Test parsing TSV format with sections."""
        # In TSV format, i7 and i5 indexes with the same name are paired
        tsv_content = """[IndexKit]
Name\tMy Index Kit
Version\t2.0

[Indices]
Name\tSequence\tIndexNumber
D701\tATTACTCG\t1
D701\tTATAGCCT\t2
D702\tTCCGGAGA\t1
D702\tATAGAGGC\t2"""

        kit = IndexParser._parse_tsv(tsv_content, "Default")

        assert kit.name == "My Index Kit"
        assert kit.version == "2.0"
        assert len(kit.index_pairs) == 2

        # Check D701 pair
        d701 = kit.get_index_pair_by_name("D701")
        assert d701 is not None
        assert d701.index1.sequence == "ATTACTCG"
        assert d701.index2.sequence == "TATAGCCT"

    def test_parse_yaml_format(self):
        """Test parsing YAML format."""
        yaml_content = """
Name: Test Kit
Version: "1.0"
Description: Test index kit
IndexSequences:
  i7Index1:
    D701: "ATTACTCG"
    D702: "TCCGGAGA"
  i5Index2:
    D701: "TATAGCCT"
    D702: "ATAGAGGC"
"""

        kit = IndexParser._parse_yaml(yaml_content, "Default")

        assert kit.name == "Test Kit"
        assert kit.version == "1.0"
        assert kit.description == "Test index kit"
        assert len(kit.index_pairs) == 2

    def test_parse_yaml_d7_d5_convention(self):
        """Test that D7xx to D5xx naming convention works."""
        yaml_content = """
Name: Test Kit
IndexSequences:
  i7Index1:
    D701: "ATTACTCG"
  i5Index2:
    D501: "TATAGCCT"
"""

        kit = IndexParser._parse_yaml(yaml_content)

        # D701 should match with D501 via naming convention
        d701 = kit.get_index_pair_by_name("D701")
        assert d701 is not None
        assert d701.index1.sequence == "ATTACTCG"
        assert d701.index2.sequence == "TATAGCCT"

    def test_parse_from_content_csv(self):
        """Test parsing from content with filename hint."""
        content = """name,index,index2
S1,ATCG,GCTA"""

        kit = IndexParser.parse_from_content(content, "indexes.csv")
        assert len(kit.index_pairs) == 1

    def test_parse_from_content_yaml(self):
        """Test parsing YAML from content (single index mode)."""
        content = """
Name: Kit
IndexSequences:
  i7Index1:
    idx1: "ATCG"
"""

        kit = IndexParser.parse_from_content(content, "kit.yaml")
        assert kit.name == "Kit"
        # When no i5 indexes are present, auto-detects as single mode
        from sequencing_run_setup.models.index import IndexMode
        assert kit.index_mode == IndexMode.SINGLE
        assert len(kit.i7_indexes) == 1
        assert kit.i7_indexes[0].sequence == "ATCG"

    def test_detect_format_yaml(self):
        """Test format detection for YAML."""
        content = """Name: Test
Version: 1.0"""

        assert IndexParser._detect_format(content) == "yaml"

    def test_detect_format_tsv(self):
        """Test format detection for TSV."""
        content = """[IndexKit]
Name\tTest"""

        assert IndexParser._detect_format(content) == "tsv"

    def test_detect_format_csv_default(self):
        """Test format detection defaults to CSV."""
        content = """name,index
S1,ATCG"""

        assert IndexParser._detect_format(content) == "csv"

    def test_empty_csv(self):
        """Test parsing empty CSV."""
        csv_content = """name,index,index2"""

        kit = IndexParser._parse_csv(csv_content, "Empty")
        assert len(kit.index_pairs) == 0

    def test_sequences_uppercase(self):
        """Test that sequences are normalized to uppercase."""
        csv_content = """name,index,index2
Sample1,atcgatcg,gctagcta"""

        kit = IndexParser._parse_csv(csv_content)
        assert kit.index_pairs[0].index1.sequence == "ATCGATCG"
        assert kit.index_pairs[0].index2.sequence == "GCTAGCTA"

    def test_parse_csv_with_well(self):
        """Test parsing CSV with well column."""
        csv_content = """name,index,index2,well
Sample1,ATCGATCG,GCTAGCTA,A1
Sample2,TTGGAATT,AACCGGTT,A2"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        assert len(kit.index_pairs) == 2
        assert kit.index_pairs[0].well_position == "A1"
        assert kit.index_pairs[0].index1.well_position == "A1"
        assert kit.index_pairs[1].well_position == "A2"

    def test_parse_csv_without_well(self):
        """Test parsing CSV without well column."""
        csv_content = """name,index,index2
Sample1,ATCGATCG,GCTAGCTA
Sample2,TTGGAATT,AACCGGTT"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        assert len(kit.index_pairs) == 2
        assert kit.index_pairs[0].well_position is None
        assert kit.index_pairs[0].index1.well_position is None
        assert kit.index_pairs[1].well_position is None

    def test_parse_csv_with_well_position_header(self):
        """Test parsing CSV with Well_Position header variant."""
        csv_content = """name,index,index2,Well_Position
Sample1,ATCGATCG,GCTAGCTA,B3
Sample2,TTGGAATT,AACCGGTT,B4"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        assert kit.index_pairs[0].well_position == "B3"
        assert kit.index_pairs[1].well_position == "B4"

    def test_parse_single_csv_with_well(self):
        """Test parsing single-index CSV with well column."""
        csv_content = """name,index,well
Sample1,ATCGATCG,A1
Sample2,TTGGAATT,A2"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        from sequencing_run_setup.models.index import IndexMode
        assert kit.index_mode == IndexMode.SINGLE
        assert len(kit.i7_indexes) == 2
        assert kit.i7_indexes[0].well_position == "A1"
        assert kit.i7_indexes[1].well_position == "A2"

    def test_parse_single_csv_without_well(self):
        """Test parsing single-index CSV without well column."""
        csv_content = """name,index
Sample1,ATCGATCG
Sample2,TTGGAATT"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        from sequencing_run_setup.models.index import IndexMode
        assert kit.index_mode == IndexMode.SINGLE
        assert len(kit.i7_indexes) == 2
        assert kit.i7_indexes[0].well_position is None
        assert kit.i7_indexes[1].well_position is None

    def test_parse_combinatorial_csv_with_well(self):
        """Test parsing combinatorial CSV with well column."""
        csv_content = """[i7]
name,sequence,well
A,ATTACTCG,A1
B,TCCGGAGA,A2

[i5]
name,sequence,well
01,TATAGCCT,B1
02,ATAGAGGC,B2"""

        kit = IndexParser._parse_combinatorial_csv(csv_content, "TestKit")

        from sequencing_run_setup.models.index import IndexMode
        assert kit.index_mode == IndexMode.COMBINATORIAL
        assert len(kit.i7_indexes) == 2
        assert len(kit.i5_indexes) == 2
        assert kit.i7_indexes[0].well_position == "A1"
        assert kit.i7_indexes[1].well_position == "A2"
        assert kit.i5_indexes[0].well_position == "B1"
        assert kit.i5_indexes[1].well_position == "B2"

    def test_parse_combinatorial_csv_without_well(self):
        """Test parsing combinatorial CSV without well column."""
        csv_content = """[i7]
name,sequence
A,ATTACTCG
B,TCCGGAGA

[i5]
name,sequence
01,TATAGCCT
02,ATAGAGGC"""

        kit = IndexParser._parse_combinatorial_csv(csv_content, "TestKit")

        from sequencing_run_setup.models.index import IndexMode
        assert kit.index_mode == IndexMode.COMBINATORIAL
        assert len(kit.i7_indexes) == 2
        assert len(kit.i5_indexes) == 2
        assert kit.i7_indexes[0].well_position is None
        assert kit.i7_indexes[1].well_position is None
        assert kit.i5_indexes[0].well_position is None
        assert kit.i5_indexes[1].well_position is None

    def test_parse_from_content_with_metadata_overrides(self):
        """Test that kit metadata can be overridden."""
        csv_content = """name,index,index2
S1,ATCG,GCTA"""

        kit = IndexParser.parse_from_content(
            csv_content,
            "original_name.csv",
            kit_name="Custom Kit Name",
            kit_version="2.5",
            kit_description="My custom description",
        )

        assert kit.name == "Custom Kit Name"
        assert kit.version == "2.5"
        assert kit.description == "My custom description"

    def test_parse_from_content_without_metadata_overrides(self):
        """Test that kit uses defaults when no overrides provided."""
        csv_content = """name,index,index2
S1,ATCG,GCTA"""

        kit = IndexParser.parse_from_content(csv_content, "my_kit_file.csv")

        assert kit.name == "my_kit_file"
        assert kit.version == "1.0"
        assert kit.description == ""

    def test_parse_from_content_partial_metadata_overrides(self):
        """Test that only provided overrides are applied."""
        csv_content = """name,index,index2
S1,ATCG,GCTA"""

        kit = IndexParser.parse_from_content(
            csv_content,
            "original.csv",
            kit_name="New Name",
            # version and description not provided
        )

        assert kit.name == "New Name"
        assert kit.version == "1.0"  # default
        assert kit.description == ""  # default

    def test_parse_csv_unique_dual_with_separate_names(self):
        """Test parsing unique dual CSV with separate i7 and i5 names."""
        csv_content = """name,i7_name,index,i5_name,index2,well
UDP0001,D701,ATTACTCG,D501,TATAGCCT,A01
UDP0002,D702,TCCGGAGA,D502,ATAGAGGC,A02"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        assert len(kit.index_pairs) == 2
        # Check first pair
        assert kit.index_pairs[0].name == "UDP0001"
        assert kit.index_pairs[0].index1.name == "D701"
        assert kit.index_pairs[0].index1.sequence == "ATTACTCG"
        assert kit.index_pairs[0].index2.name == "D501"
        assert kit.index_pairs[0].index2.sequence == "TATAGCCT"
        assert kit.index_pairs[0].well_position == "A01"
        # Check second pair
        assert kit.index_pairs[1].name == "UDP0002"
        assert kit.index_pairs[1].index1.name == "D702"
        assert kit.index_pairs[1].index2.name == "D502"

    def test_parse_csv_unique_dual_without_separate_names(self):
        """Test that pair name is used for indexes when separate names not provided."""
        csv_content = """name,index,index2
D701,ATTACTCG,TATAGCCT
D702,TCCGGAGA,ATAGAGGC"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        assert len(kit.index_pairs) == 2
        # When no separate names, pair name is used for both indexes
        assert kit.index_pairs[0].name == "D701"
        assert kit.index_pairs[0].index1.name == "D701"
        assert kit.index_pairs[0].index2.name == "D701"

    def test_parse_csv_unique_dual_partial_separate_names(self):
        """Test parsing with only i7_name provided (i5_name falls back to pair name)."""
        csv_content = """name,i7_name,index,index2
UDP0001,D701,ATTACTCG,TATAGCCT"""

        kit = IndexParser._parse_csv(csv_content, "TestKit")

        assert kit.index_pairs[0].name == "UDP0001"
        assert kit.index_pairs[0].index1.name == "D701"
        assert kit.index_pairs[0].index2.name == "UDP0001"  # falls back to pair name
