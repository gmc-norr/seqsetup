"""Sample parsing logic for pasted/uploaded sample data."""

import csv
import io
import re
from dataclasses import dataclass
from typing import Optional

from ..models.sample import (
    MAX_SAMPLE_TEXT,
    TEST_VERSION_RE,
    TEST_VERSION_RULE,
    ZERO_SAMPLE_ID_RULE,
    is_zero_only,
)
from ..models.sequencing_run import MAX_SAMPLES_PER_RUN

# DNA sequence validation pattern (compiled once at module level).
# \Z (not $) so a trailing newline can't slip through — $ also matches just
# before a final newline. Cells are stripped before this runs, but keep the
# anchor strict for defense in depth and consistency with models/index.py.
_VALID_DNA_RE = re.compile(r'^[ACGTN]*\Z')

# Per-cell character cap. Matches the 256 limit applied by routes' sanitize_string()
# on form-submitted fields, so pasted/imported values arrive at the model layer
# already bounded. A sample ID or test cell over it is refused instead, never
# cut (spec 2026-10-14 long sample text): the cut is for the cells that do not
# become one of them.
_MAX_CELL_LEN = MAX_SAMPLE_TEXT


@dataclass
class ParsedSample:
    """Parsed sample data from pasted input."""
    sample_id: str
    test_id: str = ""
    test_version: str = ""  # "1", "1.2" or "1.2.3"; checked as read
    index1_sequence: str = ""  # i7 index sequence
    index2_sequence: str = ""  # i5 index sequence
    index_pair_name: str = ""  # Name for the index pair (used as index_kit_name)
    index1_name: str = ""  # i7 index name
    index2_name: str = ""  # i5 index name
    line: int = 0  # 1-based line in the pasted text


# Common header names (case-insensitive)
# A paste may carry more than one sample-ID-ish column. They are ranked, not
# taken by position: a column that names the sample ID itself wins over
# "sample"/"id", which win over "name"/"sample_name" — the order the LIMS
# importer already reads the same aliases in (services/sample_api.py). Two
# columns of the same rank: the leftmost wins, as before.
_SAMPLE_HEADER_RANKS = (
    {"sample_id", "sampleid", "sample id", "sample-id"},
    {"sample", "id"},
    {"name", "sample_name", "samplename"},
)
SAMPLE_HEADERS = {name for rank in _SAMPLE_HEADER_RANKS for name in rank}
TEST_HEADERS = {
    "test_id", "testid", "test", "test id", "test-id",
    "test_type", "testtype", "test type", "assay", "application",
}
# Not "version" alone: a lab file may have another column of that name
# (spec 2026-10-07 group A4, §2).
TEST_VERSION_HEADERS = {
    "test_version", "testversion", "test version", "test-version",
}
# In this order in the message that refuses a column it does not read.
_INDEX1_NAMES = ("index", "index1", "i7", "index_i7", "i7_index", "index i7")
_INDEX2_NAMES = ("index2", "i5", "index_i5", "i5_index", "index i5")
INDEX1_HEADERS = set(_INDEX1_NAMES)
INDEX2_HEADERS = set(_INDEX2_NAMES)
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
    "test_version": "Test version",
    "index1": "i7",
    "index2": "i5",
    "index_pair_name": "Index name",
    "index1_name": "i7 name",
    "index2_name": "i5 name",
}

# Without a header row, columns 1-2 are read as these fields, in order, and
# a paste with more columns is refused: which column holds the i7 and which
# the i5 is never guessed (index mix-up audit, 2026-10-14; the user's choice
# "Refuse, say why").
_HEADERLESS_FIELDS = ("sample_id", "test_id")

# A header word that marks an index or lane column: such a column must be
# one the paste reads, or the paste is refused (same audit and choice).
_INDEX_OR_LANE_WORD = re.compile(r"^(index|barcode|i7|i5|lane)")


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


def _sample_id_column(header_parts: list[str]) -> Optional[int]:
    """Which column holds the sample ID: the best-ranked sample header, and
    among equals the leftmost. A paste headed Sample_Name, Sample_ID stored
    the name as the sample ID and dropped the lab's own ID."""
    best: Optional[tuple[int, int]] = None
    for i, col in enumerate(header_parts):
        col_lower = col.lower().strip()
        for rank, names in enumerate(_SAMPLE_HEADER_RANKS):
            if col_lower in names:
                if best is None or rank < best[0]:
                    best = (rank, i)
                break
    return None if best is None else best[1]


def _detect_column_mapping(header_parts: list[str]) -> dict[str, int]:
    """
    Detect which columns contain which fields based on header row.

    Args:
        header_parts: List of header column values

    Returns:
        Dictionary mapping field names to column indices
    """
    mapping = {}
    sample_id_column = _sample_id_column(header_parts)
    if sample_id_column is not None:
        mapping["sample_id"] = sample_id_column
    for i, col in enumerate(header_parts):
        col_lower = col.lower().strip()
        if col_lower in SAMPLE_HEADERS:
            continue
        elif col_lower in TEST_HEADERS and "test_id" not in mapping:
            mapping["test_id"] = i
        elif col_lower in TEST_VERSION_HEADERS and "test_version" not in mapping:
            mapping["test_version"] = i
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

    # Check if any column matches known headers. A sample header counts in
    # any column: "Well, Sample_ID" is a header row, not a sample named Well.
    all_headers = (
        SAMPLE_HEADERS | TEST_HEADERS | TEST_VERSION_HEADERS | INDEX1_HEADERS | INDEX2_HEADERS
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


def _no_header_error(lines: list[int]) -> ValueError:
    """Reject the whole paste: no header row, and more than two columns."""
    return ValueError(
        f"Row(s) {', '.join(str(n) for n in lines)}: this paste has no header row, and "
        f"these rows have more than two columns. Without a header row SeqSetup reads only "
        f"the sample ID (first column) and the test (second column); it does not guess which "
        f"column holds which index. Add a header row naming the columns, for example: "
        f"sample_id, test_id, index_i7, index_i5."
    )


def _unread_columns_error(names: list[str]) -> ValueError:
    """Reject the whole paste: a header column looks like an index or a lane
    but is not a column the paste reads."""
    quoted = ", ".join(f'"{name}"' for name in names)
    lanes = any(
        word.startswith("lane")
        for name in names for word in re.split(r"[^a-z0-9]+", name.lower())
    )
    return ValueError(
        f"Column(s) {quoted}: SeqSetup does not read these, so the whole paste was "
        f"refused. The i7 is read from a column named {', '.join(_INDEX1_NAMES[:-1])} or "
        f"{_INDEX1_NAMES[-1]}; the i5 from {', '.join(_INDEX2_NAMES[:-1])} or "
        f"{_INDEX2_NAMES[-1]}."
        + (" Lanes come from the Lanes picker, not from the paste." if lanes else "")
        + " Rename or remove the column(s), or keep one column for each index."
    )


def _looks_like_index_or_lane(name: str) -> bool:
    return any(_INDEX_OR_LANE_WORD.match(word) for word in re.split(r"[^a-z0-9]+", name.lower()))


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
    # The columns of each line whose cell was longer than _MAX_CELL_LEN,
    # before the cut, so a sample ID or test that long is refused.
    long_cells: dict[int, set[int]] = {}
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
        cells = [cell.strip() for cell in raw]
        rows.append((line_no, [cell[:_MAX_CELL_LEN] for cell in cells]))
        long_cells[line_no] = {k for k, cell in enumerate(cells) if len(cell) > _MAX_CELL_LEN}

    if rows and not _is_header_row(rows[0][1]):
        wide = [line_no for line_no, parts in rows if any(parts[len(_HEADERLESS_FIELDS):])]
        if wide:
            raise _no_header_error(wide)

    # Default column mapping (no header)
    column_mapping = {"sample_id": 0, "test_id": 1}
    header_detected = False

    # Track row numbers that had content but no sample_id, so the caller can
    # see exactly which rows were rejected. Silent drop is a clinical-safety
    # smell — a 96-sample worklist missing one row would silently produce a
    # 95-sample run with no indication anything was lost.
    rows_missing_sample_id: list[int] = []
    rows_zero_sample_id: list[int] = []
    rows_long_sample_id: list[int] = []
    rows_long_test: list[int] = []
    rows_bad_version: list[int] = []

    for i, (source_line, parts) in enumerate(rows):
        # Check first non-empty line for header
        if i == 0 and _is_header_row(parts):
            column_mapping = _detect_column_mapping(parts)
            # Ensure sample_id has a mapping (default to first column if not found)
            if "sample_id" not in column_mapping:
                column_mapping["sample_id"] = 0
            unread = [name for k, name in enumerate(parts)
                      if k not in column_mapping.values() and _looks_like_index_or_lane(name)]
            if unread:
                raise _unread_columns_error(unread)
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

        if "index2" in column_mapping and len(parts) > column_mapping["index2"]:
            index2 = parts[column_mapping["index2"]]

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

        if is_zero_only(sample_id):
            # The model refuses it, so the whole paste is refused here —
            # naming its rows, like a row with no sample ID at all.
            rows_zero_sample_id.append(source_line)
            continue

        # A sample ID or test longer than the cut is refused, never cut: the
        # cut one is another ID (spec 2026-10-14 long sample text).
        too_long = long_cells.get(source_line, set())
        if column_mapping.get("sample_id", 0) in too_long:
            rows_long_sample_id.append(source_line)
            continue
        if column_mapping.get("test_id", None if header_detected else 1) in too_long:
            rows_long_test.append(source_line)
            continue

        # A version is at most 29 characters, so a cell cut to _MAX_CELL_LEN
        # is still refused: no cut makes a version good (spec 2026-10-07
        # group A4, §2).
        test_version = ""
        if "test_version" in column_mapping and len(parts) > column_mapping["test_version"]:
            test_version = parts[column_mapping["test_version"]]
        if test_version and not TEST_VERSION_RE.match(test_version):
            rows_bad_version.append(source_line)
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
            test_version=test_version,
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
    if rows_zero_sample_id:
        rows_str = ", ".join(str(n) for n in rows_zero_sample_id)
        raise ValueError(
            f"Row(s) {rows_str}: {ZERO_SAMPLE_ID_RULE}. "
            f"Give the sample its real ID or remove the row entirely."
        )
    for long_rows, what in ((rows_long_sample_id, "the sample_id"), (rows_long_test, "the test")):
        if long_rows:
            rows_str = ", ".join(str(n) for n in long_rows)
            raise ValueError(
                f"Row(s) {rows_str}: {what} is longer than {MAX_SAMPLE_TEXT} characters. "
                f"SeqSetup does not shorten it; shorten it in the source."
            )
    if rows_bad_version:
        rows_str = ", ".join(str(n) for n in rows_bad_version)
        raise ValueError(f"Row(s) {rows_str}: the test version is not right. {TEST_VERSION_RULE}.")

    used, unused = _describe_columns(rows, header_detected, column_mapping)
    return PasteReadResult(samples, header_detected, used, unused)


def parse_pasted_samples(paste_data: str) -> list[ParsedSample]:
    """Parse pasted sample data; see read_pasted_samples."""
    return read_pasted_samples(paste_data).samples
