"""Read a CSV or TSV table, keeping the line each row came from
(docs/design/2026-10-18-input-rules-design.md, "Step 3: index kit files,
every format").

A kit CSV's columns decide which sequence is the i7 and which the i5, so two
columns of one name are refused **before any row is read**: the reader takes
one of them and the other's sequences go nowhere. ``_columns_not_read`` in
``services/index_parser.py`` refuses two *different* spellings of one normal
form (``index_2`` beside ``Index2``); two columns spelt the same way were
accepted and the last one won.
"""

import csv
import re
from dataclasses import dataclass
from io import StringIO
from typing import Optional

from .kits import KitFileRefused


class ColumnGivenTwice(KitFileRefused):
    """A table whose header names one column twice. The same fault as
    ``ColumnsNotRead``, and audited under the same reason."""

    reason = "columns_not_read"


class TableNotRead(KitFileRefused):
    """A row ``csv`` cannot read strictly: a quoted cell with text after its
    closing quote, or a quote that is never closed. Read loosely, the first
    gave ``P1,"ACGT"NNNN`` the sequence ACGTNNNN and the second took the rest
    of the file into one cell (outside review of 51eb3c4, P2-2). ``line`` is
    the line the row starts on."""

    reason = "table_not_read"
    what = ('this line could not be read -- check it for a double quote (") that is not '
            'closed, or for text after a closing quote')

    def __init__(self, line: int):
        self.line = line
        super().__init__(f"Line {line}: {self.what}. Nothing was saved.")


class CellOverLines(TableNotRead):
    """A quoted cell holding a line break: the rows after it merge into the
    cell and go nowhere, as the paste refuses (services/sample_parser.py)."""

    what = ('a cell runs over more than one line -- a double quote (") that is not closed '
            "where it should be, or a line break inside a cell; the rows after it would "
            "merge into it")


def column_key(name) -> str:
    """One normal form for a column name: lower case, no spaces and no
    underscores, so ``INDEX``, ``Index`` and ``index_2`` read as the columns
    they plainly are."""
    return re.sub(r"[\s_]+", "", str(name).strip().lower())


@dataclass(frozen=True)
class Row:
    """One row of the table: the line it is on in the file, the cells by the
    header names as written, and the cells under no column name."""

    line: int
    cells: dict
    extra: list


@dataclass(frozen=True)
class Table:
    header: Optional[list]
    rows: list


def read_table(text: str, line_offset: int = 0, delimiter: str = ",") -> Table:
    """The table's header and rows, each row with its own line number.

    ``line_offset`` is how many lines were taken off the front of ``text``
    before it was read, so a row names the file's own line. Raises
    ``ColumnGivenTwice`` when the header names one column twice, and
    ``TableNotRead`` for a row whose quotes do not close.
    """
    reader = csv.DictReader(StringIO(text), delimiter=delimiter, strict=True)
    # A record starts on the line after the one the last record ended on.
    start = 1
    try:
        # Before any row: reading the header is what DictReader's fieldnames does.
        refuse_repeated_columns(reader.fieldnames)
        if _over_lines(reader.fieldnames or []):
            raise CellOverLines(1 + line_offset)
        rows = []
        while True:
            start = reader.line_num + 1
            try:
                row = next(reader)
            except StopIteration:
                break
            extra = list(row.pop(None, None) or [])
            if _over_lines([*row.values(), *extra]):
                raise CellOverLines(start + line_offset)
            rows.append(Row(reader.line_num + line_offset, row, extra))
    except csv.Error:
        raise TableNotRead(start + line_offset) from None
    return Table(reader.fieldnames, rows)


def _over_lines(cells) -> bool:
    return any(isinstance(cell, str) and ("\n" in cell or "\r" in cell) for cell in cells)


def refuse_repeated_columns(names) -> None:
    """Refuse a header that names one column twice, in the same spelling or
    in two spellings of one normal form."""
    seen: dict = {}
    for name in names or []:
        if not name:
            continue
        key = column_key(name)
        if key in seen:
            first = seen[key]
            both = (f'two columns named "{name}"' if first == name
                    else f'two columns, "{first}" and "{name}", that name one column')
            raise ColumnGivenTwice(
                f"The file's header has {both}, so nothing was saved: the reader would "
                f"take one of them and the other's values would go nowhere. Keep one."
            )
        seen[key] = name
