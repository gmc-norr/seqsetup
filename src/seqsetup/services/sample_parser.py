"""Sample parsing logic for pasted/uploaded sample data."""

import csv
import io
import re
from dataclasses import dataclass

from ..models.sequencing_run import MAX_SAMPLES_PER_RUN

# DNA sequence validation pattern (compiled once at module level).
# \Z (not $) so a trailing newline can't slip through — $ also matches just
# before a final newline. Cells are stripped before this runs, but keep the
# anchor strict for defense in depth and consistency with models/index.py.
_VALID_DNA_RE = re.compile(r'^[ACGTN]*\Z')

# Per-cell character cap. Matches the 256 limit applied by routes' sanitize_string()
# on form-submitted fields, so pasted/imported values arrive at the model layer
# already bounded.
_MAX_CELL_LEN = 256


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
    line: int = 0  # 1-based line in the pasted text


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

# Display names for the preview's "Columns used" line.
FIELD_LABELS = {
    "sample_id": "Sample ID",
    "test_id": "Test",
    "index1": "i7",
    "index2": "i5",
    "index_pair_name": "Index name",
    "index1_name": "i7 name",
    "index2_name": "i5 name",
}

# Without a header row, columns 1-4 are read as these fields, in order.
_HEADERLESS_FIELDS = ("sample_id", "test_id", "index1", "index2")


@dataclass
class PasteReadResult:
    """What the parser read from a paste, and how it read the columns.

    columns_used pairs each source column (its header text, or "column N"
    when there is no header row) with the field it was read as;
    columns_unused lists source columns holding data that no field took.
    """
    samples: list[ParsedSample]
    header_found: bool
    columns_used: list[tuple[str, str]]
    columns_unused: list[str]


def _describe_columns(
    rows: list[tuple[int, list[str]]],
    header_found: bool,
    column_mapping: dict[str, int],
) -> tuple[list[tuple[str, str]], list[str]]:
    """Which source columns were read as which field, and which were not."""
    data_rows = rows[1:] if header_found else rows
    filled = {i for _line, parts in data_rows for i, cell in enumerate(parts) if cell}
    if header_found:
        header = rows[0][1]
        names = {
            i: header[i] if i < len(header) and header[i] else f"column {i + 1}"
            for i in set(range(len(header))) | filled
        }
        taken = {i: field for field, i in column_mapping.items()}
    else:
        names = {i: f"column {i + 1}" for i in filled}
        taken = dict(enumerate(_HEADERLESS_FIELDS))
    used = [(names[i], FIELD_LABELS[taken[i]]) for i in sorted(names) if i in taken]
    unused = [names[i] for i in sorted(names) if i not in taken and i in filled]
    return used, unused


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


def _detect_delimiter(paste_data: str) -> str:
    """Pick a single delimiter for the whole file.

    Tab wins over comma when present anywhere — pasted CSV-from-spreadsheet
    is almost always tab-delimited; only explicit comma-only paste uses ','.
    Picking once per file (rather than per line) lets us use csv.reader,
    which handles quoting correctly — a row with a quoted comma in the
    sample ID would otherwise misparse and shift every downstream column.
    """
    if "\t" in paste_data:
        return "\t"
    return ","


def _unreadable_line_error(line_no: int) -> ValueError:
    """Reject the whole paste: csv could not read this record (e.g. an
    unclosed quote, or text after a closing quote)."""
    return ValueError(
        f'Line {line_no}: this line could not be read — check it for a double '
        f'quote (") that is not closed correctly, then paste again.'
    )


def _multiline_cell_error(line_no: int) -> ValueError:
    """Reject the whole paste: a cell spanning lines means rows were merged
    into it, so samples would silently vanish."""
    return ValueError(
        f"Line {line_no}: a cell runs over more than one line — a double "
        f'quote (") that is not closed, or a line break inside a cell. Rows '
        f"would be merged, so fix it and paste again."
    )


def read_pasted_samples(paste_data: str) -> PasteReadResult:
    """
    Parse pasted sample data.

    Supports:
    - Tab or comma-separated columns (delimiter chosen for the whole input)
    - Quoted fields (RFC 4180) so a sample ID containing a comma stays
      intact rather than splitting the row
    - Optional header row (auto-detected and used for column mapping)
    - Columns: sample_id, test_id, index_i7, index_i5, index_pair_name, i7_name, i5_name

    Args:
        paste_data: Raw pasted text

    Returns:
        PasteReadResult
    """
    samples = []
    if not paste_data or not paste_data.strip():
        return PasteReadResult([], False, [], [])

    # Strip a leading UTF-8 BOM (﻿). Excel and many LIMS exports prepend
    # one; without this it would embed in the first header cell (e.g.
    # "﻿sample_id"), break header detection, and cause the column
    # mapping to silently fall back to default order — routing the wrong
    # values into the wrong fields.
    if paste_data.startswith("﻿"):
        paste_data = paste_data[1:]

    # Old-Mac CR-only line endings are line breaks (csv.reader would raise on
    # them). Normalizing CRLF too keeps line numbers the same for all three.
    paste_data = paste_data.replace("\r\n", "\n").replace("\r", "\n")

    delimiter = _detect_delimiter(paste_data)
    # strict=True: an unclosed quote or text after a closing quote ('"S2"x')
    # raises instead of being silently repaired.
    reader = csv.reader(io.StringIO(paste_data), delimiter=delimiter, strict=True)
    # Capture (file_line_no, clamped_parts) per non-blank row so error
    # messages can name the actual source line the user can find in their
    # file. csv.reader.line_num is 1-based and tracks the input stream
    # position regardless of blank-row filtering. A record starts on the line
    # after the previous record ended.
    rows: list[tuple[int, list[str]]] = []
    start_line = 1
    while True:
        try:
            raw = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:
            raise _unreadable_line_error(start_line) from exc
        # A cell holding a line break means a quote opened on one line and
        # closed on a later one: every row in between was merged into it.
        if any("\n" in cell for cell in raw):
            raise _multiline_cell_error(start_line)
        line_no, start_line = start_line, reader.line_num + 1
        if not any(cell.strip() for cell in raw):
            continue  # skip wholly blank rows
        # Clamp each cell to MAX_CELL_LEN per the CLAUDE.md input-sanitization
        # rule; downstream code assumes bounded strings (model invariants, DB
        # field widths, render budgets).
        rows.append((line_no, [cell.strip()[:_MAX_CELL_LEN] for cell in raw]))

    # Default column mapping (no header)
    column_mapping = {"sample_id": 0, "test_id": 1, "index1": 2, "index2": 3}
    header_detected = False

    # Track row numbers that had content but no sample_id, so the caller can
    # see exactly which rows were rejected. Silent drop is a clinical-safety
    # smell — a 96-sample worklist missing one row would silently produce a
    # 95-sample run with no indication anything was lost.
    rows_missing_sample_id: list[int] = []

    for i, (source_line, parts) in enumerate(rows):
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

        if not sample_id:
            # A row with content in any column but no sample_id is a data
            # error — silently skipping would land that lab sample in the
            # demultiplexer's "Undetermined" bucket. Record the row and
            # reject the whole import after the loop.
            rows_missing_sample_id.append(source_line)
            continue

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

        if len(samples) >= MAX_SAMPLES_PER_RUN:
            # Stop as soon as the cap is exceeded rather than materialising
            # millions of rows from a huge paste (a DoS vector) and deferring
            # the failure. Reject the whole import per the clinical default.
            raise ValueError(
                f"Too many samples: a run accepts a maximum of {MAX_SAMPLES_PER_RUN}. "
                f"Reduce the worklist or split it across runs."
            )

        samples.append(ParsedSample(
            sample_id=sample_id,
            test_id=test_id,
            index1_sequence=index1_upper,
            index2_sequence=index2_upper,
            index_pair_name=index_pair_name,
            index1_name=index1_name,
            index2_name=index2_name,
            line=source_line,
        ))

    if rows_missing_sample_id:
        rows_str = ", ".join(str(n) for n in rows_missing_sample_id)
        raise ValueError(
            f"Row(s) {rows_str}: sample_id is required. "
            f"Either supply a sample_id or remove the row entirely."
        )

    used, unused = _describe_columns(rows, header_detected, column_mapping)
    return PasteReadResult(samples, header_detected, used, unused)


def parse_pasted_samples(paste_data: str) -> list[ParsedSample]:
    """Parse pasted sample data; see read_pasted_samples."""
    return read_pasted_samples(paste_data).samples
