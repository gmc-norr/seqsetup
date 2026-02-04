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
        """Test parsing a minimal kit with only required fields."""
        yaml_content = """
name: "Minimal Kit"
index_pairs:
  - name: "P1"
    index1:
      name: "i7"
      sequence: "ATCG"
"""
        kit = IndexKitSyncParser.parse(yaml_content, "minimal.yaml")

        assert kit is not None
        assert kit.name == "Minimal Kit"
        assert kit.version == "1.0"  # Default
        assert kit.index_mode == IndexMode.UNIQUE_DUAL  # Default

    def test_parse_invalid_yaml(self):
        """Test parsing invalid YAML returns None."""
        yaml_content = """
invalid: yaml: content
  - broken
"""
        kit = IndexKitSyncParser.parse(yaml_content, "invalid.yaml")
        assert kit is None

    def test_parse_empty_content(self):
        """Test parsing empty content returns None."""
        kit = IndexKitSyncParser.parse("", "empty.yaml")
        assert kit is None

    def test_parse_derives_name_from_filename(self):
        """Test that name is derived from filename if not provided."""
        yaml_content = """
version: "1.0"
index_pairs:
  - name: "P1"
    index1:
      name: "i7"
      sequence: "ATCG"
"""
        kit = IndexKitSyncParser.parse(yaml_content, "my_custom_kit.yaml")

        assert kit is not None
        assert kit.name == "My Custom Kit"

    def test_parse_with_well_positions(self):
        """Test parsing index pairs with well positions."""
        yaml_content = """
name: "Plate Kit"
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
adapter_read1: "ADAPTER1"
adapter_read2: "ADAPTER2"
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
        assert kit.adapter_read1 == "ADAPTER1"
        assert kit.adapter_read2 == "ADAPTER2"
        assert kit.default_index1_cycles == 10
        assert kit.default_index2_cycles == 10
        assert kit.default_read1_override == "Y*"
        assert kit.default_read2_override == "N2Y*"
