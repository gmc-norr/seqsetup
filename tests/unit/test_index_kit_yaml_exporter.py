"""Tests for IndexKitYamlExporter."""

import yaml
import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.services.index_kit_yaml_exporter import IndexKitYamlExporter


class TestIndexKitYamlExporter:
    """Tests for IndexKitYamlExporter."""

    def test_export_unique_dual_kit(self):
        """Test exporting a unique dual index kit."""
        kit = IndexKit(
            name="Test UDI Kit",
            version="2.0",
            description="Test description",
            index_mode=IndexMode.UNIQUE_DUAL,
            is_fixed_layout=True,
            adapter_read1="CTGTCTCT",
            default_index1_cycles=8,
            index_pairs=[
                IndexPair(
                    id="pair1",
                    name="UDI0001",
                    well_position="A01",
                    index1=Index(name="i7-001", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="i5-001", sequence="TATAGCCT", index_type=IndexType.I5),
                ),
            ],
        )

        yaml_str = IndexKitYamlExporter.export(kit)
        data = yaml.safe_load(yaml_str)

        assert data["name"] == "Test UDI Kit"
        assert data["version"] == "2.0"
        assert data["description"] == "Test description"
        assert data["index_mode"] == "unique_dual"
        assert data["is_fixed_layout"] is True
        assert data["adapter_read1"] == "CTGTCTCT"
        assert data["default_index1_cycles"] == 8
        assert len(data["index_pairs"]) == 1
        assert data["index_pairs"][0]["name"] == "UDI0001"
        assert data["index_pairs"][0]["well_position"] == "A01"
        assert data["index_pairs"][0]["index1"]["sequence"] == "ATTACTCG"

    def test_export_combinatorial_kit(self):
        """Test exporting a combinatorial index kit."""
        kit = IndexKit(
            name="Nextera XT",
            version="1.0",
            index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[
                Index(name="N701", sequence="ATTACTCG", index_type=IndexType.I7),
                Index(name="N702", sequence="TCCGGAGA", index_type=IndexType.I7),
            ],
            i5_indexes=[
                Index(name="S501", sequence="TATAGCCT", index_type=IndexType.I5),
                Index(name="S502", sequence="ATAGAGGC", index_type=IndexType.I5),
            ],
        )

        yaml_str = IndexKitYamlExporter.export(kit)
        data = yaml.safe_load(yaml_str)

        assert data["name"] == "Nextera XT"
        assert data["index_mode"] == "combinatorial"
        assert len(data["i7_indexes"]) == 2
        assert len(data["i5_indexes"]) == 2
        assert data["i7_indexes"][0]["name"] == "N701"
        assert data["i5_indexes"][0]["sequence"] == "TATAGCCT"

    def test_export_single_kit(self):
        """Test exporting a single index kit."""
        kit = IndexKit(
            name="Single Kit",
            version="1.0",
            index_mode=IndexMode.SINGLE,
            i7_indexes=[
                Index(name="i7-001", sequence="ATTACTCG", index_type=IndexType.I7),
                Index(name="i7-002", sequence="TCCGGAGA", index_type=IndexType.I7),
            ],
        )

        yaml_str = IndexKitYamlExporter.export(kit)
        data = yaml.safe_load(yaml_str)

        assert data["name"] == "Single Kit"
        assert data["index_mode"] == "single"
        assert len(data["i7_indexes"]) == 2
        assert "i5_indexes" not in data

    def test_export_with_all_optional_fields(self):
        """Test exporting a kit with all optional fields."""
        kit = IndexKit(
            name="Full Kit",
            version="3.0",
            description="Full description",
            comments="Some comments",
            index_mode=IndexMode.UNIQUE_DUAL,
            is_fixed_layout=True,
            adapter_read1="ADAPTER1",
            adapter_read2="ADAPTER2",
            default_index1_cycles=10,
            default_index2_cycles=10,
            default_read1_override="U8Y*",
            default_read2_override="N2Y*",
            index_pairs=[
                IndexPair(
                    id="pair1",
                    name="P1",
                    index1=Index(name="i7", sequence="ATCGATCG", index_type=IndexType.I7),
                    index2=Index(name="i5", sequence="GCTAGCTA", index_type=IndexType.I5),
                ),
            ],
        )

        yaml_str = IndexKitYamlExporter.export(kit)
        data = yaml.safe_load(yaml_str)

        assert data["description"] == "Full description"
        assert data["comments"] == "Some comments"
        assert data["adapter_read1"] == "ADAPTER1"
        assert data["adapter_read2"] == "ADAPTER2"
        assert data["default_index1_cycles"] == 10
        assert data["default_index2_cycles"] == 10
        assert data["default_read1_override"] == "U8Y*"
        assert data["default_read2_override"] == "N2Y*"

    def test_export_omits_empty_optional_fields(self):
        """Test that empty optional fields are not included in export."""
        kit = IndexKit(
            name="Minimal Kit",
            version="1.0",
            index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[
                IndexPair(
                    id="pair1",
                    name="P1",
                    index1=Index(name="i7", sequence="ATCGATCG", index_type=IndexType.I7),
                ),
            ],
        )

        yaml_str = IndexKitYamlExporter.export(kit)
        data = yaml.safe_load(yaml_str)

        assert "description" not in data
        assert "comments" not in data
        assert "adapter_read1" not in data
        assert "adapter_read2" not in data
        assert "default_index1_cycles" not in data
        assert "default_read1_override" not in data
        assert "is_fixed_layout" not in data  # False is not included

    def test_get_filename(self):
        """Test filename generation."""
        kit = IndexKit(name="IDT for Illumina DNA/RNA", version="2.0")
        filename = IndexKitYamlExporter.get_filename(kit)
        assert filename == "idt_for_illumina_dna-rna_v2_0.yaml"

    def test_get_filename_special_chars(self):
        """Test filename generation with special characters."""
        kit = IndexKit(name="My Kit (Test)", version="1.0.0")
        filename = IndexKitYamlExporter.get_filename(kit)
        # Special chars like () are removed
        assert ".yaml" in filename
        assert "my_kit" in filename.lower()

    def test_roundtrip_unique_dual(self):
        """Test that export -> import produces equivalent kit."""
        from seqsetup.services.index_kit_sync_parser import IndexKitSyncParser

        original = IndexKit(
            name="Roundtrip Test",
            version="1.0",
            description="Test kit",
            index_mode=IndexMode.UNIQUE_DUAL,
            adapter_read1="CTGTCTCT",
            default_index1_cycles=8,
            index_pairs=[
                IndexPair(
                    id="pair1",
                    name="UDI0001",
                    well_position="A01",
                    index1=Index(name="i7-001", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="i5-001", sequence="TATAGCCT", index_type=IndexType.I5),
                ),
            ],
        )

        # Export to YAML
        yaml_str = IndexKitYamlExporter.export(original)

        # Import back
        imported = IndexKitSyncParser.parse(yaml_str, "test.yaml")

        assert imported is not None
        assert imported.name == original.name
        assert imported.version == original.version
        assert imported.description == original.description
        assert imported.index_mode == original.index_mode
        assert imported.adapter_read1 == original.adapter_read1
        assert imported.default_index1_cycles == original.default_index1_cycles
        assert len(imported.index_pairs) == len(original.index_pairs)
        assert imported.index_pairs[0].name == original.index_pairs[0].name
        assert imported.index_pairs[0].index1.sequence == original.index_pairs[0].index1.sequence
