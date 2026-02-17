"""Sample parsing logic for pasted/uploaded sample data."""

import re
from dataclasses import dataclass

# DNA sequence validation pattern (compiled once at module level)
_VALID_DNA_RE = re.compile(r'^[ACGTN]*$')


@dataclass
class ParsedSample:
    """Parsed sample data from pasted input."""
    sample_id: str
    test_id: str = ""
    index1_sequence: str = ""  # i7 index sequence
    index2_sequence: str = ""  # i5 index sequence
    index_pair_name: str = ""  # Name for the index pair (used as index_kit_name)
    index1_name: str = ""  # i7 index name
    index2_name: str = ""  # i5 index name


# Common header names (case-insensitive)
SAMPLE_HEADERS = {
    "sample_id", "sampleid", "sample", "sample id",
    "sample-id", "id", "name", "sample_name", "samplename",
}
TEST_HEADERS = {
    "test_id", "testid", "test", "test id", "test-id",
    "test_type", "testtype", "test type", "assay", "application",
}
INDEX1_HEADERS = {
    "index", "index1", "i7", "index_i7", "i7_index", "index i7",
}
INDEX2_HEADERS = {
    "index2", "i5", "index_i5", "i5_index", "index i5",
}
INDEX_PAIR_NAME_HEADERS = {
    "index_pair_name", "pair_name", "index_pair", "index pair",
    "index_kit", "kit_name", "kit name", "index kit",
}
INDEX1_NAME_HEADERS = {
    "i7_name", "i7 name", "index_i7_name", "index1_name",
    "index_name", "index name",
}
INDEX2_NAME_HEADERS = {
    "i5_name", "i5 name", "index_i5_name", "index2_name",
}


def _detect_column_mapping(header_parts: list[str]) -> dict[str, int]:
    """
    Detect which columns contain which fields based on header row.

    Args:
        header_parts: List of header column values

    Returns:
        Dictionary mapping field names to column indices
    """
    mapping = {}
    for i, col in enumerate(header_parts):
        col_lower = col.lower().strip()
        if col_lower in SAMPLE_HEADERS and "sample_id" not in mapping:
            mapping["sample_id"] = i
        elif col_lower in TEST_HEADERS and "test_id" not in mapping:
            mapping["test_id"] = i
        elif col_lower in INDEX1_NAME_HEADERS and "index1_name" not in mapping:
            # Check name headers before sequence headers (index_name is more
            # specific than index which could match INDEX1_HEADERS)
            mapping["index1_name"] = i
        elif col_lower in INDEX2_NAME_HEADERS and "index2_name" not in mapping:
            mapping["index2_name"] = i
        elif col_lower in INDEX1_HEADERS and "index1" not in mapping:
            mapping["index1"] = i
        elif col_lower in INDEX2_HEADERS and "index2" not in mapping:
            mapping["index2"] = i
        elif col_lower in INDEX_PAIR_NAME_HEADERS and "index_pair_name" not in mapping:
            mapping["index_pair_name"] = i
    return mapping


def _is_header_row(parts: list[str]) -> bool:
    """
    Check if a row appears to be a header row.

    Args:
        parts: List of column values from the row

    Returns:
        True if the row looks like a header
    """
    if not parts:
        return False

    first_lower = parts[0].lower().strip()

    # Check if first column matches a sample header
    if first_lower in SAMPLE_HEADERS:
        return True

    # Check if any column matches known headers
    all_headers = (
        TEST_HEADERS | INDEX1_HEADERS | INDEX2_HEADERS
        | INDEX_PAIR_NAME_HEADERS | INDEX1_NAME_HEADERS | INDEX2_NAME_HEADERS
    )
    for col in parts[1:]:
        col_lower = col.lower().strip()
        if col_lower in all_headers:
            return True

    return False


def parse_pasted_samples(paste_data: str) -> list[ParsedSample]:
    """
    Parse pasted sample data.

    Supports:
    - Tab or comma-separated columns
    - Optional header row (auto-detected and used for column mapping)
    - Columns: sample_id, test_id, index_i7, index_i5, index_pair_name, i7_name, i5_name

    Args:
        paste_data: Raw pasted text

    Returns:
        List of ParsedSample objects
    """
    samples = []
    lines = paste_data.strip().split("\n")

    # Default column mapping (no header)
    column_mapping = {"sample_id": 0, "test_id": 1, "index1": 2, "index2": 3}
    header_detected = False

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # Try tab separator first, then comma
        if "\t" in line:
            parts = [p.strip() for p in line.split("\t")]
        elif "," in line:
            parts = [p.strip() for p in line.split(",")]
        else:
            parts = [line.strip()]

        # Check first non-empty line for header
        if i == 0 and _is_header_row(parts):
            column_mapping = _detect_column_mapping(parts)
            # Ensure sample_id has a mapping (default to first column if not found)
            if "sample_id" not in column_mapping:
                column_mapping["sample_id"] = 0
            header_detected = True
            continue

        # Extract values using column mapping
        sample_id = parts[column_mapping.get("sample_id", 0)] if len(parts) > column_mapping.get("sample_id", 0) else ""
        test_id = ""
        index1 = ""
        index2 = ""

        if "test_id" in column_mapping and len(parts) > column_mapping["test_id"]:
            test_id = parts[column_mapping["test_id"]]
        elif not header_detected and len(parts) > 1:
            # Default: second column is test_id if no header
            test_id = parts[1]

        if "index1" in column_mapping and len(parts) > column_mapping["index1"]:
            index1 = parts[column_mapping["index1"]]
        elif not header_detected and len(parts) > 2:
            # Default: third column is index1 if no header
            index1 = parts[2]

        if "index2" in column_mapping and len(parts) > column_mapping["index2"]:
            index2 = parts[column_mapping["index2"]]
        elif not header_detected and len(parts) > 3:
            # Default: fourth column is index2 if no header
            index2 = parts[3]

        # Name columns (only when header is detected, no default positions)
        index_pair_name = ""
        index1_name = ""
        index2_name = ""

        if "index_pair_name" in column_mapping and len(parts) > column_mapping["index_pair_name"]:
            index_pair_name = parts[column_mapping["index_pair_name"]]
        if "index1_name" in column_mapping and len(parts) > column_mapping["index1_name"]:
            index1_name = parts[column_mapping["index1_name"]]
        if "index2_name" in column_mapping and len(parts) > column_mapping["index2_name"]:
            index2_name = parts[column_mapping["index2_name"]]

        if sample_id:
            # Validate DNA sequences (allow empty, but reject invalid chars)
            index1_upper = index1.upper() if index1 else ""
            index2_upper = index2.upper() if index2 else ""

            # Check for invalid DNA characters
            if index1_upper and not _VALID_DNA_RE.match(index1_upper):
                invalid_chars = set(index1_upper) - set("ACGTN")
                raise ValueError(
                    f"Invalid characters in index1 for sample '{sample_id}': {invalid_chars}. "
                    f"Only A, C, G, T, N are allowed."
                )
            if index2_upper and not _VALID_DNA_RE.match(index2_upper):
                invalid_chars = set(index2_upper) - set("ACGTN")
                raise ValueError(
                    f"Invalid characters in index2 for sample '{sample_id}': {invalid_chars}. "
                    f"Only A, C, G, T, N are allowed."
                )

            samples.append(ParsedSample(
                sample_id=sample_id,
                test_id=test_id,
                index1_sequence=index1_upper,
                index2_sequence=index2_upper,
                index_pair_name=index_pair_name,
                index1_name=index1_name,
                index2_name=index2_name,
            ))

    return samples
