"""Export IndexKit objects to YAML format for download."""

from typing import Any

import yaml

from ..models.index import IndexKit, IndexMode


class IndexKitYamlExporter:
    """Export IndexKit objects to YAML format.

    Generates YAML files compatible with the GitHub sync format,
    allowing users to download index kits for backup or sharing.
    """

    @classmethod
    def export(cls, kit: IndexKit) -> str:
        """Export an IndexKit to YAML string.

        Args:
            kit: The IndexKit to export

        Returns:
            YAML formatted string
        """
        data = cls._build_yaml_dict(kit)
        return yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
        )

    @classmethod
    def _build_yaml_dict(cls, kit: IndexKit) -> dict[str, Any]:
        """Build the YAML dictionary structure from an IndexKit.

        Args:
            kit: The IndexKit to convert

        Returns:
            Dictionary ready for YAML serialization
        """
        data: dict[str, Any] = {}

        # Required fields
        data["name"] = kit.name
        data["version"] = kit.version

        # Optional metadata
        if kit.description:
            data["description"] = kit.description
        if kit.comments:
            data["comments"] = kit.comments

        # Index mode
        data["index_mode"] = kit.index_mode.value

        # Layout settings
        if kit.is_fixed_layout:
            data["is_fixed_layout"] = kit.is_fixed_layout

        # Adapter sequences
        if kit.adapter_read1:
            data["adapter_read1"] = kit.adapter_read1
        if kit.adapter_read2:
            data["adapter_read2"] = kit.adapter_read2

        # Override cycle defaults
        if kit.default_index1_cycles is not None:
            data["default_index1_cycles"] = kit.default_index1_cycles
        if kit.default_index2_cycles is not None:
            data["default_index2_cycles"] = kit.default_index2_cycles

        # Read override patterns
        if kit.default_read1_override:
            data["default_read1_override"] = kit.default_read1_override
        if kit.default_read2_override:
            data["default_read2_override"] = kit.default_read2_override

        # Index data based on mode
        if kit.index_mode == IndexMode.UNIQUE_DUAL:
            data["index_pairs"] = cls._export_index_pairs(kit)
        elif kit.index_mode == IndexMode.COMBINATORIAL:
            data["i7_indexes"] = cls._export_indexes(kit.i7_indexes)
            data["i5_indexes"] = cls._export_indexes(kit.i5_indexes)
        elif kit.index_mode == IndexMode.SINGLE:
            data["i7_indexes"] = cls._export_indexes(kit.i7_indexes)

        return data

    @classmethod
    def _export_index_pairs(cls, kit: IndexKit) -> list[dict[str, Any]]:
        """Export index pairs to list of dictionaries.

        Args:
            kit: The IndexKit containing the pairs

        Returns:
            List of pair dictionaries
        """
        pairs = []
        for pair in kit.index_pairs:
            pair_data: dict[str, Any] = {"name": pair.name}

            if pair.well_position:
                pair_data["well_position"] = pair.well_position

            # Index 1 (i7)
            index1_data: dict[str, Any] = {
                "name": pair.index1.name,
                "sequence": pair.index1.sequence,
            }
            if pair.index1.well_position:
                index1_data["well_position"] = pair.index1.well_position
            pair_data["index1"] = index1_data

            # Index 2 (i5) - optional
            if pair.index2:
                index2_data: dict[str, Any] = {
                    "name": pair.index2.name,
                    "sequence": pair.index2.sequence,
                }
                if pair.index2.well_position:
                    index2_data["well_position"] = pair.index2.well_position
                pair_data["index2"] = index2_data

            pairs.append(pair_data)

        return pairs

    @classmethod
    def _export_indexes(cls, indexes: list) -> list[dict[str, Any]]:
        """Export individual indexes to list of dictionaries.

        Args:
            indexes: List of Index objects

        Returns:
            List of index dictionaries
        """
        result = []
        for idx in indexes:
            idx_data: dict[str, Any] = {
                "name": idx.name,
                "sequence": idx.sequence,
            }
            if idx.well_position:
                idx_data["well_position"] = idx.well_position
            result.append(idx_data)

        return result

    @classmethod
    def get_filename(cls, kit: IndexKit) -> str:
        """Generate a safe filename for the YAML export.

        Args:
            kit: The IndexKit being exported

        Returns:
            Safe filename with .yaml extension
        """
        # Create filename from kit name and version
        safe_name = kit.name.lower().replace(" ", "_").replace("/", "-")
        # Remove any other problematic characters
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "_-")
        safe_version = kit.version.replace(".", "_")
        return f"{safe_name}_v{safe_version}.yaml"
