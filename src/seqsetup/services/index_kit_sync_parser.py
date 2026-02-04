"""Parser for index kit YAML files from GitHub sync."""

import logging
from typing import Optional

import yaml

from ..models.index import Index, IndexKit, IndexMode, IndexPair, IndexType

logger = logging.getLogger(__name__)


class IndexKitSyncParser:
    """Parse index kit YAML files from GitHub sync format.

    The sync YAML format supports all IndexKit fields:

    ```yaml
    name: "Kit Name"
    version: "1.0"
    description: "Description"
    comments: "Notes"
    index_mode: unique_dual  # unique_dual | combinatorial | single
    is_fixed_layout: true

    # Optional adapter sequences
    adapter_read1: "SEQUENCE"
    adapter_read2: "SEQUENCE"

    # Optional override cycles
    default_index1_cycles: 8
    default_index2_cycles: 8
    default_read1_override: "Y*"
    default_read2_override: "Y*"

    # For unique_dual mode:
    index_pairs:
      - name: "Pair1"
        well_position: "A01"
        index1:
          name: "i7-name"
          sequence: "ATCGATCG"
        index2:
          name: "i5-name"
          sequence: "GCTAGCTA"

    # For combinatorial/single mode:
    i7_indexes:
      - name: "N701"
        sequence: "ATTACTCG"
        well_position: "A01"
    i5_indexes:  # Only for combinatorial mode
      - name: "S501"
        sequence: "TATAGCCT"
    ```
    """

    @classmethod
    def parse(cls, yaml_content: str, source_file: str) -> Optional[IndexKit]:
        """Parse YAML content into IndexKit.

        Args:
            yaml_content: YAML string content
            source_file: Source filename for logging

        Returns:
            IndexKit if parsing succeeds, None otherwise
        """
        try:
            data = yaml.safe_load(yaml_content)
            if not data:
                logger.warning(f"Empty YAML content in {source_file}")
                return None
            return cls._parse_kit(data, source_file)
        except yaml.YAMLError as e:
            logger.warning(f"Failed to parse YAML from {source_file}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Failed to process index kit from {source_file}: {e}")
            return None

    @classmethod
    def _parse_kit(cls, data: dict, source_file: str) -> IndexKit:
        """Parse dict data into IndexKit."""
        # Parse index mode
        mode_str = data.get("index_mode", "unique_dual")
        try:
            index_mode = IndexMode(mode_str)
        except ValueError:
            logger.warning(
                f"Unknown index_mode '{mode_str}' in {source_file}, defaulting to unique_dual"
            )
            index_mode = IndexMode.UNIQUE_DUAL

        name = data.get("name", "")
        if not name:
            # Derive name from filename if not provided
            name = source_file.replace(".yaml", "").replace(".yml", "").replace("_", " ").title()

        kit = IndexKit(
            name=name,
            version=str(data.get("version", "1.0")),
            description=data.get("description", ""),
            comments=data.get("comments", ""),
            index_mode=index_mode,
            is_fixed_layout=data.get("is_fixed_layout", False),
            adapter_read1=data.get("adapter_read1"),
            adapter_read2=data.get("adapter_read2"),
            default_index1_cycles=data.get("default_index1_cycles"),
            default_index2_cycles=data.get("default_index2_cycles"),
            default_read1_override=data.get("default_read1_override"),
            default_read2_override=data.get("default_read2_override"),
            created_by="github_sync",
            source="github",
        )

        # Parse indexes based on mode
        if index_mode == IndexMode.UNIQUE_DUAL:
            kit.index_pairs = cls._parse_index_pairs(data.get("index_pairs", []), kit.name)
        else:
            kit.i7_indexes = cls._parse_indexes(data.get("i7_indexes", []), IndexType.I7)
            if index_mode == IndexMode.COMBINATORIAL:
                kit.i5_indexes = cls._parse_indexes(data.get("i5_indexes", []), IndexType.I5)

        return kit

    @classmethod
    def _parse_index_pairs(cls, pairs_data: list, kit_name: str) -> list[IndexPair]:
        """Parse index pairs from YAML data."""
        pairs = []
        for i, pair_data in enumerate(pairs_data):
            name = pair_data.get("name", f"Pair_{i + 1}")

            # Parse index1 (i7)
            i1_data = pair_data.get("index1", {})
            index1 = Index(
                name=i1_data.get("name", name),
                sequence=i1_data.get("sequence", ""),
                index_type=IndexType.I7,
                well_position=i1_data.get("well_position"),
            )

            # Parse index2 (i5) - optional
            index2 = None
            i2_data = pair_data.get("index2")
            if i2_data:
                index2 = Index(
                    name=i2_data.get("name", name),
                    sequence=i2_data.get("sequence", ""),
                    index_type=IndexType.I5,
                    well_position=i2_data.get("well_position"),
                )

            pairs.append(
                IndexPair(
                    id=f"{kit_name}_{name}",
                    name=name,
                    index1=index1,
                    index2=index2,
                    well_position=pair_data.get("well_position"),
                )
            )

        return pairs

    @classmethod
    def _parse_indexes(cls, indexes_data: list, index_type: IndexType) -> list[Index]:
        """Parse individual indexes from YAML data."""
        indexes = []
        for idx_data in indexes_data:
            indexes.append(
                Index(
                    name=idx_data.get("name", ""),
                    sequence=idx_data.get("sequence", ""),
                    index_type=index_type,
                    well_position=idx_data.get("well_position"),
                )
            )
        return indexes
