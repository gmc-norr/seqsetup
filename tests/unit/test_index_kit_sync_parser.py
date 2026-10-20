"""Tests for IndexKitSyncParser."""

import pytest

from seqsetup.models.index import IndexMode
from seqsetup.services.index_kit_sync_parser import IndexKitSyncParser


class TestIndexKitSyncParser:
    """Tests for IndexKitSyncParser."""

    def test_parse_unique_dual_kit(self):
        """Test parsing a unique dual index kit."""
        yaml_content = """
name: "Test UDI Kit"
version: "2.0"
description: "Test description"
index_mode: unique_dual
is_fixed_layout: true
adapter_read1: "CTGTCTCT"
default_index1_cycles: 8

index_pairs:
  - name: "UDI0001"
    well_position: "A01"
    index1:
      name: "i7-001"
      sequence: "ATTACTCG"
    index2:
      name: "i5-001"
      sequence: "TATAGCCT"
  - name: "UDI0002"
    index1:
      name: "i7-002"
      sequence: "TCCGGAGA"
    index2:
      name: "i5-002"
      sequence: "ATAGAGGC"
"""
        kit = IndexKitSyncParser.parse(yaml_content, "test.yaml")

        assert kit is not None
        assert kit.name == "Test UDI Kit"
        assert kit.version == "2.0"
        assert kit.description == "Test description"
        assert kit.index_mode == IndexMode.UNIQUE_DUAL
        assert kit.is_fixed_layout is True
        assert kit.adapter_read1 == "CTGTCTCT"
        assert kit.default_index1_cycles == 8
        assert kit.source == "github"
        assert kit.created_by == "github_sync"

        assert len(kit.index_pairs) == 2
        assert kit.index_pairs[0].name == "UDI0001"
        assert kit.index_pairs[0].well_position == "A01"
        assert kit.index_pairs[0].index1.sequence == "ATTACTCG"
        assert kit.index_pairs[0].index2.sequence == "TATAGCCT"

    def test_parse_combinatorial_kit(self):
        """Test parsing a combinatorial index kit."""
        yaml_content = """
name: "Nextera XT"
version: "1.0"
index_mode: combinatorial

i7_indexes:
  - name: "N701"
    sequence: "ATTACTCG"
  - name: "N702"
    sequence: "TCCGGAGA"

i5_indexes:
  - name: "S501"
    sequence: "TATAGCCT"
  - name: "S502"
    sequence: "ATAGAGGC"
"""
        kit = IndexKitSyncParser.parse(yaml_content, "nextera.yaml")

        assert kit is not None
        assert kit.name == "Nextera XT"
        assert kit.index_mode == IndexMode.COMBINATORIAL
        assert len(kit.i7_indexes) == 2
        assert len(kit.i5_indexes) == 2
        assert kit.i7_indexes[0].name == "N701"
        assert kit.i7_indexes[0].sequence == "ATTACTCG"
        assert kit.source == "github"

    def test_parse_single_kit(self):
        """Test parsing a single index kit."""
        yaml_content = """
name: "Single Index Kit"
version: "1.0"
index_mode: single

i7_indexes:
  - name: "i7-001"
    sequence: "ATTACTCG"
  - name: "i7-002"
    sequence: "TCCGGAGA"
"""
        kit = IndexKitSyncParser.parse(yaml_content, "single.yaml")

        assert kit is not None
        assert kit.index_mode == IndexMode.SINGLE
        assert len(kit.i7_indexes) == 2
        assert len(kit.i5_indexes) == 0

    def test_parse_minimal_kit(self):
        """A synced file must write its version and its mode out: they were
        defaulted to "1.0" and unique_dual, so the file's own name decided the
        identity a sync compares and a wrong mode was never seen."""
        yaml_content = """
name: "Minimal Kit"
index_pairs:
  - name: "P1"
    index1:
      name: "i7"
      sequence: "ATCG"
"""
        with pytest.raises(ValueError) as refused:
            IndexKitSyncParser.parse(yaml_content, "minimal.yaml")

        message = str(refused.value)
        assert "version" in message and "index_mode" in message, message
        assert "is required" in message, message

    def test_parse_invalid_yaml(self):
        """Test parsing invalid YAML returns None."""
        yaml_content = """
invalid: yaml: content
  - broken
"""
        kit = IndexKitSyncParser.parse(yaml_content, "invalid.yaml")
        assert kit is None

    def test_parse_unknown_index_mode_rejected(self):
        """Unknown index_mode must NOT silently fall back to unique_dual —
        round-tripping `combinatorial` → corrupted → `unique_dual` would
        silently change the assay model. Reject by returning None."""
        yaml_content = """
name: "Kit"
version: "1.0"
index_mode: "totally_made_up_mode"
index_pairs:
  - name: "P1"
    index1:
      name: "i7"
      sequence: "ATCG"
"""
        with pytest.raises(ValueError) as refused:
            IndexKitSyncParser.parse(yaml_content, "bogus_mode.yaml")

        message = str(refused.value)
        assert "index_mode" in message and "line 4" in message, message

    def test_parse_empty_content(self):
        """Test parsing empty content returns None."""
        kit = IndexKitSyncParser.parse("", "empty.yaml")
        assert kit is None

    def test_parse_refuses_a_file_that_names_no_kit(self):
        """A file with no name was stored under the file's own name made into
        a title ("my_custom_kit.yaml" -> "My Custom Kit"), so the file's name
        decided the identity the next sync compares."""
        yaml_content = """
version: "1.0"
index_mode: unique_dual
index_pairs:
  - name: "P1"
    index1:
      name: "i7"
      sequence: "ATCG"
"""
        with pytest.raises(ValueError) as refused:
            IndexKitSyncParser.parse(yaml_content, "my_custom_kit.yaml")

        assert "name" in str(refused.value) and "is required" in str(refused.value)

    def test_parse_with_well_positions(self):
        """Test parsing index pairs with well positions."""
        yaml_content = """
name: "Plate Kit"
version: "1.0"
index_mode: unique_dual
is_fixed_layout: true
index_pairs:
  - name: "P1"
    well_position: "A01"
    index1:
      name: "i7-A01"
      sequence: "ATCGATCG"
      well_position: "A01"
    index2:
      name: "i5-A01"
      sequence: "GCTAGCTA"
"""
        kit = IndexKitSyncParser.parse(yaml_content, "plate.yaml")

        assert kit is not None
        assert kit.is_fixed_layout is True
        assert kit.index_pairs[0].well_position == "A01"
        assert kit.index_pairs[0].index1.well_position == "A01"

    def test_parse_with_all_optional_fields(self):
        """Test parsing a kit with all optional fields."""
        yaml_content = """
name: "Full Kit"
version: "3.0"
description: "Full description"
comments: "Some comments"
index_mode: unique_dual
is_fixed_layout: true
adapter_read1: "ACGTACGTACGT"
adapter_read2: "TGCATGCATGCA"
default_index1_cycles: 10
default_index2_cycles: 10
default_read1_override: "Y*"
default_read2_override: "N2Y*"

index_pairs:
  - name: "P1"
    index1:
      name: "i7"
      sequence: "ATCGATCG"
    index2:
      name: "i5"
      sequence: "GCTAGCTA"
"""
        kit = IndexKitSyncParser.parse(yaml_content, "full.yaml")

        assert kit is not None
        assert kit.description == "Full description"
        assert kit.comments == "Some comments"
        assert kit.adapter_read1 == "ACGTACGTACGT"
        assert kit.adapter_read2 == "TGCATGCATGCA"
        assert kit.default_index1_cycles == 10
        assert kit.default_index2_cycles == 10
        assert kit.default_read1_override == "Y*"
        assert kit.default_read2_override == "N2Y*"


class TestEveryProblemOfAFileComesBack:
    """``parse`` could say only the first thing wrong, as one exception; the
    sync needs them all for the Config Sync page and its audit row, so
    ``check`` gives a CheckResult like step 2's profile checkers."""

    def test_check_gives_every_problem_with_its_line(self):
        content = ('name: "K"\nversion: 1\nindex_mode: single\nownr: me\n'
                   'i7_indexes:\n  - name: A\n    sequence: ACGT\n')

        result = IndexKitSyncParser.check(content, "k.yaml")

        assert not result.ok
        assert [(p.line, tuple(p.path)) for p in result.problems] == [
            (2, ("version",)), (4, ("ownr",))]

    def test_check_gives_the_value_a_good_file_describes(self):
        result = IndexKitSyncParser.check(GOOD_FOR_CHECK, "k.yaml")

        assert result.ok
        assert result.value.name == "Checked kit"

    def test_a_file_that_cannot_be_read_at_all_still_comes_back_as_none(self):
        assert IndexKitSyncParser.parse("name: [unclosed\n", "k.yaml") is None
        assert IndexKitSyncParser.parse("", "k.yaml") is None


GOOD_FOR_CHECK = """\
name: "Checked kit"
version: "1.0"
index_mode: single
i7_indexes:
  - name: A1
    sequence: ATTACTCG
"""
