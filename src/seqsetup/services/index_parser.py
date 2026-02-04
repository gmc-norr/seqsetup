"""Parse index adapter kit files in various formats."""

import csv
import re
from io import StringIO
from pathlib import Path
from typing import Optional

import yaml

from ..models.index import Index, IndexKit, IndexMode, IndexPair, IndexType


# Semantic version pattern: X.Y.Z or X.Y (where X, Y, Z are non-negative integers)
SEMVER_PATTERN = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?$")


def validate_semantic_version(version: str) -> tuple[bool, str]:
    """Validate that a version string follows semantic versioning.

    Args:
        version: Version string to validate

    Returns:
        Tuple of (is_valid, error_message). error_message is empty if valid.
    """
    version = version.strip()
    if not version:
        return False, "Version is required"

    if not SEMVER_PATTERN.match(version):
        return False, f"Version '{version}' is not valid semantic versioning. Use format: X.Y or X.Y.Z (e.g., 1.0, 2.1.3)"

    return True, ""


def normalize_version(version: str) -> str:
    """Normalize a version string to ensure consistent format.

    Args:
        version: Version string to normalize

    Returns:
        Normalized version (e.g., "1" becomes "1.0")
    """
    version = version.strip()

    # If just a number, add .0
    if version.isdigit():
        return f"{version}.0"

    return version


class IndexParser:
    """Parse index adapter kit files in various formats."""

    @classmethod
    def parse(
        cls,
        file_path: Path,
        file_content: Optional[str] = None,
        index_mode: Optional[IndexMode] = None,
    ) -> IndexKit:
        """
        Parse index file based on extension.

        Args:
            file_path: Path to the file (used for extension detection)
            file_content: Optional file content string. If not provided, reads from file_path.
            index_mode: Index mode (unique_dual, combinatorial, single). If None, auto-detects.

        Returns:
            IndexKit with parsed indexes
        """
        suffix = file_path.suffix.lower()
        content = file_content if file_content is not None else file_path.read_text()

        if suffix in (".yaml", ".yml"):
            return cls._parse_yaml(content, file_path.stem, index_mode)
        elif suffix == ".tsv":
            return cls._parse_tsv(content, file_path.stem, index_mode)
        elif suffix == ".csv":
            return cls._parse_csv(content, file_path.stem, index_mode)
        else:
            raise ValueError(f"Unsupported file format: {suffix}")

    @classmethod
    def parse_from_content(
        cls,
        content: str,
        filename: str,
        format_hint: Optional[str] = None,
        index_mode: Optional[IndexMode] = None,
        kit_name: Optional[str] = None,
        kit_version: Optional[str] = None,
        kit_description: Optional[str] = None,
    ) -> IndexKit:
        """
        Parse index content directly with format hint.

        Args:
            content: File content as string
            filename: Original filename (for naming the kit)
            format_hint: Format type ("yaml", "tsv", "csv") or None to auto-detect
            index_mode: Index mode (unique_dual, combinatorial, single). If None, auto-detects.
            kit_name: Optional override for kit name (defaults to filename stem)
            kit_version: Optional override for kit version (defaults to "1.0")
            kit_description: Optional override for kit description (defaults to "")

        Returns:
            IndexKit with parsed indexes
        """
        if format_hint is None:
            # Auto-detect format
            if filename.endswith((".yaml", ".yml")):
                format_hint = "yaml"
            elif filename.endswith(".tsv"):
                format_hint = "tsv"
            elif filename.endswith(".csv"):
                format_hint = "csv"
            else:
                # Try to detect from content
                format_hint = cls._detect_format(content)

        default_name = kit_name or Path(filename).stem

        if format_hint == "yaml":
            kit = cls._parse_yaml(content, default_name, index_mode)
        elif format_hint == "tsv":
            kit = cls._parse_tsv(content, default_name, index_mode)
        elif format_hint == "csv":
            kit = cls._parse_csv(content, default_name, index_mode)
        else:
            raise ValueError(f"Could not determine format for {filename}")

        # Apply metadata overrides if provided
        if kit_name:
            kit.name = kit_name
        if kit_version:
            kit.version = kit_version
        if kit_description:
            kit.description = kit_description

        return kit

    @classmethod
    def _detect_format(cls, content: str) -> str:
        """Detect format from content."""
        content = content.strip()

        # Check for YAML indicators
        if content.startswith("---") or ":" in content.split("\n")[0]:
            try:
                yaml.safe_load(content)
                return "yaml"
            except yaml.YAMLError:
                pass

        # Check for TSV (sections with brackets)
        if content.startswith("["):
            return "tsv"

        # Default to CSV
        return "csv"

    @classmethod
    def _parse_yaml(
        cls,
        content: str,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
    ) -> IndexKit:
        """
        Parse YAML index kit file.

        Supports two formats:

        1. Sync format (GitHub sync / export format):
           name: "Kit Name"
           version: "1.0"
           index_mode: unique_dual
           index_pairs:
             - name: "UDI0001"
               index1:
                 name: "i7-001"
                 sequence: "ATTACTCG"

        2. Legacy Illumina format:
           Name: Kit Name
           Version: "1.0"
           IndexSequences:
             i7Index1:
               D701: "ATTACTCG"
        """
        data = yaml.safe_load(content)

        if not data:
            raise ValueError("Empty or invalid YAML content")

        # Detect format: sync format has "index_pairs" or "i7_indexes" keys
        is_sync_format = (
            "index_pairs" in data
            or "i7_indexes" in data
            or "index_mode" in data
        )

        if is_sync_format:
            return cls._parse_sync_yaml(data, default_name, index_mode)
        else:
            return cls._parse_illumina_yaml(data, default_name, index_mode)

    @classmethod
    def _parse_sync_yaml(
        cls,
        data: dict,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
    ) -> IndexKit:
        """Parse sync/export YAML format."""
        # Get index mode from file or parameter
        mode_str = data.get("index_mode", "unique_dual")
        file_mode = IndexMode(mode_str) if mode_str else IndexMode.UNIQUE_DUAL
        mode = index_mode or file_mode

        kit = IndexKit(
            name=data.get("name", default_name),
            version=normalize_version(str(data.get("version", "1.0"))),
            description=data.get("description", ""),
            comments=data.get("comments", ""),
            index_mode=mode,
            is_fixed_layout=data.get("is_fixed_layout", False),
            adapter_read1=data.get("adapter_read1"),
            adapter_read2=data.get("adapter_read2"),
            default_index1_cycles=data.get("default_index1_cycles"),
            default_index2_cycles=data.get("default_index2_cycles"),
            default_read1_override=data.get("default_read1_override"),
            default_read2_override=data.get("default_read2_override"),
        )

        # Parse index_pairs for unique_dual mode
        if "index_pairs" in data:
            for pair_data in data["index_pairs"]:
                i1_data = pair_data.get("index1", {})
                i2_data = pair_data.get("index2")

                index1 = Index(
                    name=i1_data.get("name", ""),
                    sequence=i1_data.get("sequence", ""),
                    index_type=IndexType.I7,
                    well_position=i1_data.get("well_position"),
                )

                index2 = None
                if i2_data:
                    index2 = Index(
                        name=i2_data.get("name", ""),
                        sequence=i2_data.get("sequence", ""),
                        index_type=IndexType.I5,
                        well_position=i2_data.get("well_position"),
                    )

                pair_name = pair_data.get("name", index1.name)
                pair = IndexPair(
                    id=f"{kit.name}_{pair_name}",
                    name=pair_name,
                    index1=index1,
                    index2=index2,
                    well_position=pair_data.get("well_position"),
                )
                kit.index_pairs.append(pair)

        # Parse i7_indexes for combinatorial/single mode
        if "i7_indexes" in data:
            for idx_data in data["i7_indexes"]:
                kit.i7_indexes.append(
                    Index(
                        name=idx_data.get("name", ""),
                        sequence=idx_data.get("sequence", ""),
                        index_type=IndexType.I7,
                        well_position=idx_data.get("well_position"),
                    )
                )

        # Parse i5_indexes for combinatorial mode
        if "i5_indexes" in data:
            for idx_data in data["i5_indexes"]:
                kit.i5_indexes.append(
                    Index(
                        name=idx_data.get("name", ""),
                        sequence=idx_data.get("sequence", ""),
                        index_type=IndexType.I5,
                        well_position=idx_data.get("well_position"),
                    )
                )

        return kit

    @classmethod
    def _parse_illumina_yaml(
        cls,
        data: dict,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
    ) -> IndexKit:
        """Parse legacy Illumina YAML format."""
        # Parse index sequences
        index_seqs = data.get("IndexSequences", {})
        i7_indexes = index_seqs.get("i7Index1", {}) or index_seqs.get("Index1", {})
        i5_indexes = index_seqs.get("i5Index2", {}) or index_seqs.get("Index2", {})

        # Auto-detect mode if not specified
        if index_mode is None:
            if not i5_indexes:
                index_mode = IndexMode.SINGLE
            else:
                index_mode = IndexMode.UNIQUE_DUAL

        kit = IndexKit(
            name=data.get("Name", default_name),
            version=normalize_version(str(data.get("Version", "1.0"))),
            description=data.get("Description", ""),
            index_mode=index_mode,
        )

        if index_mode == IndexMode.COMBINATORIAL:
            # Store indexes separately for combinatorial mode
            for name, seq in i7_indexes.items():
                kit.i7_indexes.append(Index(name=name, sequence=seq, index_type=IndexType.I7))
            for name, seq in i5_indexes.items():
                kit.i5_indexes.append(Index(name=name, sequence=seq, index_type=IndexType.I5))
        elif index_mode == IndexMode.SINGLE:
            # Store only i7 indexes for single mode
            for name, seq in i7_indexes.items():
                kit.i7_indexes.append(Index(name=name, sequence=seq, index_type=IndexType.I7))
        else:
            # Build index pairs for unique_dual mode
            for i7_name, i7_seq in i7_indexes.items():
                index1 = Index(name=i7_name, sequence=i7_seq, index_type=IndexType.I7)

                # Try to find matching i5 index
                index2 = None
                potential_i5_names = [
                    i7_name,
                    i7_name.replace("D7", "D5"),
                    i7_name.replace("-A", "-B"),
                    i7_name.replace("_A", "_B"),
                ]

                for i5_name in potential_i5_names:
                    if i5_name in i5_indexes:
                        index2 = Index(
                            name=i5_name,
                            sequence=i5_indexes[i5_name],
                            index_type=IndexType.I5,
                        )
                        break

                pair = IndexPair(
                    id=f"{kit.name}_{i7_name}",
                    name=i7_name,
                    index1=index1,
                    index2=index2,
                )
                kit.index_pairs.append(pair)

        return kit

    @classmethod
    def _parse_tsv(
        cls,
        content: str,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
    ) -> IndexKit:
        """
        Parse TSV index kit file (Illumina template format).

        Expected format:
        [IndexKit]
        Name<tab>Kit Name
        Version<tab>1.0

        [Indices]
        Name<tab>Sequence<tab>IndexNumber
        D701<tab>ATTACTCG<tab>1
        D501<tab>TATAGCCT<tab>2
        """
        lines = content.strip().split("\n")
        current_section = None
        i7_indexes: dict[str, str] = {}
        i5_indexes: dict[str, str] = {}
        kit_name = default_name
        kit_version = "1.0"
        kit_description = ""

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith("["):
                current_section = line.strip("[]")
                continue

            parts = line.split("\t")

            if current_section == "IndexKit":
                if len(parts) >= 2:
                    key, value = parts[0], parts[1]
                    if key == "Name":
                        kit_name = value
                    elif key == "Version":
                        kit_version = value
                    elif key == "Description":
                        kit_description = value

            elif current_section == "Indices":
                if len(parts) >= 3:
                    name, seq, index_num = parts[0], parts[1], parts[2]
                    if index_num == "1":
                        i7_indexes[name] = seq
                    elif index_num == "2":
                        i5_indexes[name] = seq

        # Auto-detect mode if not specified
        if index_mode is None:
            if not i5_indexes:
                index_mode = IndexMode.SINGLE
            else:
                index_mode = IndexMode.UNIQUE_DUAL

        kit = IndexKit(
            name=kit_name,
            version=kit_version,
            description=kit_description,
            index_mode=index_mode,
        )

        if index_mode == IndexMode.COMBINATORIAL:
            # Store indexes separately for combinatorial mode
            for name, seq in i7_indexes.items():
                kit.i7_indexes.append(Index(name=name, sequence=seq, index_type=IndexType.I7))
            for name, seq in i5_indexes.items():
                kit.i5_indexes.append(Index(name=name, sequence=seq, index_type=IndexType.I5))
        elif index_mode == IndexMode.SINGLE:
            # Store only i7 indexes for single mode
            for name, seq in i7_indexes.items():
                kit.i7_indexes.append(Index(name=name, sequence=seq, index_type=IndexType.I7))
        else:
            # Build index pairs for unique_dual mode
            for name, seq in i7_indexes.items():
                index1 = Index(name=name, sequence=seq, index_type=IndexType.I7)
                index2 = None
                if name in i5_indexes:
                    index2 = Index(
                        name=name, sequence=i5_indexes[name], index_type=IndexType.I5
                    )

                kit.index_pairs.append(
                    IndexPair(
                        id=f"{kit.name}_{name}",
                        name=name,
                        index1=index1,
                        index2=index2,
                    )
                )

        return kit

    @classmethod
    def _parse_csv(
        cls,
        content: str,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
    ) -> IndexKit:
        """
        Parse CSV index file.

        Supports two formats:

        1. Simple format (for unique_dual or single mode):
           name,index,index2
           D701,ATTACTCG,TATAGCCT

        2. Combinatorial format (for combinatorial mode):
           [i7]
           name,sequence
           A,ATTACTCG

           [i5]
           name,sequence
           01,TATAGCCT
        """
        content = content.strip()

        # Check if this is combinatorial format (has [i7] section)
        if content.startswith("[i7]") or "\n[i7]" in content:
            return cls._parse_combinatorial_csv(content, default_name, index_mode)

        # Parse simple format
        reader = csv.DictReader(StringIO(content))
        rows = list(reader)

        # Check for i5 sequences to auto-detect mode
        has_i5 = False
        for row in rows:
            i5_seq = (
                row.get("index2")
                or row.get("Index2")
                or row.get("i5")
                or row.get("Index_2")
                or ""
            )
            if i5_seq:
                has_i5 = True
                break

        # Auto-detect mode if not specified
        if index_mode is None:
            if not has_i5:
                index_mode = IndexMode.SINGLE
            else:
                index_mode = IndexMode.UNIQUE_DUAL

        kit = IndexKit(name=default_name, version="1.0", description="", index_mode=index_mode)

        for row in rows:
            # Find pair/combination name column
            name = (
                row.get("name")
                or row.get("Name")
                or row.get("Sample_ID")
                or row.get("sample_id")
                or ""
            )

            # Find i7 name column (optional, falls back to pair name)
            i7_name = (
                row.get("i7_name")
                or row.get("I7_Name")
                or row.get("i7_index_name")
                or name
            )

            # Find i5 name column (optional, falls back to pair name)
            i5_name = (
                row.get("i5_name")
                or row.get("I5_Name")
                or row.get("i5_index_name")
                or name
            )

            # Find i7 sequence column
            i7_seq = (
                row.get("index")
                or row.get("Index")
                or row.get("i7")
                or row.get("Index1")
                or row.get("index1")
                or row.get("sequence")
                or row.get("Sequence")
                or ""
            )

            # Find i5 sequence column (optional)
            i5_seq = (
                row.get("index2")
                or row.get("Index2")
                or row.get("i5")
                or row.get("Index_2")
                or ""
            )

            # Find well position column (optional)
            well = (
                row.get("well")
                or row.get("Well")
                or row.get("well_position")
                or row.get("Well_Position")
                or None
            )

            if name and i7_seq:
                if index_mode == IndexMode.SINGLE:
                    # Store as individual indexes
                    kit.i7_indexes.append(
                        Index(name=name, sequence=i7_seq, index_type=IndexType.I7, well_position=well)
                    )
                else:
                    # Store as index pairs (unique_dual mode)
                    index1 = Index(name=i7_name, sequence=i7_seq, index_type=IndexType.I7, well_position=well)
                    index2 = (
                        Index(name=i5_name, sequence=i5_seq, index_type=IndexType.I5, well_position=well)
                        if i5_seq
                        else None
                    )

                    kit.index_pairs.append(
                        IndexPair(
                            id=f"{kit.name}_{name}",
                            name=name,
                            index1=index1,
                            index2=index2,
                            well_position=well,
                        )
                    )

        return kit

    @classmethod
    def _parse_combinatorial_csv(
        cls,
        content: str,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
    ) -> IndexKit:
        """
        Parse combinatorial CSV format with [i7] and [i5] sections.

        Expected format:
        [i7]
        name,sequence
        A,ATTACTCG
        B,TCCGGAGA

        [i5]
        name,sequence
        01,TATAGCCT
        02,ATAGAGGC
        """
        # Force combinatorial mode for this format
        if index_mode is None:
            index_mode = IndexMode.COMBINATORIAL

        kit = IndexKit(
            name=default_name,
            version="1.0",
            description="",
            index_mode=index_mode,
        )

        lines = content.strip().split("\n")
        current_section = None
        section_lines: list[str] = []

        def process_section():
            nonlocal section_lines
            if not section_lines or current_section is None:
                return

            section_content = "\n".join(section_lines)
            reader = csv.DictReader(StringIO(section_content))

            for row in reader:
                name = row.get("name") or row.get("Name") or ""
                seq = row.get("sequence") or row.get("Sequence") or ""
                well = (
                    row.get("well")
                    or row.get("Well")
                    or row.get("well_position")
                    or row.get("Well_Position")
                    or None
                )

                if name and seq:
                    if current_section == "i7":
                        kit.i7_indexes.append(
                            Index(name=name, sequence=seq, index_type=IndexType.I7, well_position=well)
                        )
                    elif current_section == "i5":
                        kit.i5_indexes.append(
                            Index(name=name, sequence=seq, index_type=IndexType.I5, well_position=well)
                        )

            section_lines = []

        for line in lines:
            line = line.strip()

            if line.lower() == "[i7]":
                process_section()
                current_section = "i7"
            elif line.lower() == "[i5]":
                process_section()
                current_section = "i5"
            elif line:
                section_lines.append(line)

        # Process last section
        process_section()

        return kit
