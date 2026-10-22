"""Parse index adapter kit files in various formats."""

import re
from pathlib import Path
from typing import Optional

import yaml

from ..input_rules.kits import KitFileProblems, KitFileRefused, build_kit, check_kit_data
from ..input_rules.reader import GIVEN_TWICE, Locations, read_yaml
from ..input_rules.table import ColumnGivenTwice, TableNotRead, read_table
from ..utils.yaml_safety import safe_load_strict

from ..models.index import IndexKit, IndexMode
from .sheet_text import describe, hidden_characters


class UnpairedIndexes(KitFileRefused):
    """A Unique Dual kit file whose i7 and i5 indexes do not pair up by name.

    An Illumina YAML or TSV file lists its i7 and i5 indexes apart; an i7 is
    paired only with the i5 of the same name. Pairs were once guessed from
    names that look alike (D701 with D501, -A with -B, _A with _B), so a
    combinatorial kit was saved as fixed pairs and a sample could be given an
    i5 its tube does not have.
    """

    reason = "unpaired_indexes"


class RepeatedNames(KitFileRefused):
    """A kit file that gives one name twice in one list. Only the second
    entry was kept: the first index vanished and its name carried the
    other's sequence."""

    reason = "repeated_names"


class IndexNamesNotText(KitFileRefused):
    """An Illumina YAML file whose index names or sequences YAML does not
    read as text: an unquoted 012 is the number 10 and yes is true, so two
    names written differently could be taken as one."""

    reason = "index_names_not_text"


class I5DataInSingleKit(KitFileRefused):
    """A kit file uploaded as Single whose content carries i5 data.

    A Single kit saves the i7 indexes only, so the file's i5 column, i5Index2
    list, IndexNumber 2 lines, [i5] section or i5_indexes list went nowhere --
    or into a kit whose panel never shows them. The admin was told nothing.
    """

    reason = "i5_data_in_single_kit"


class PairsInSingleKit(KitFileRefused):
    """A SeqSetup-format kit file uploaded as Single that lists index_pairs.

    A Single kit hands out single i7 indexes; its panel reads i7_indexes and
    never the pairs, so every pair in the file went unused and unseen.
    """

    reason = "pairs_in_single_kit"


class IncompleteIndexRows(KitFileRefused):
    """A kit file with a line that has content but is not an index.

    A CSV row with no name or no i7 sequence, and a TSV [Indices] line with
    fewer than three cells or an index number that is neither 1 nor 2, were
    dropped without a word: the kit saved fewer indexes than the file listed.
    """

    reason = "incomplete_index_rows"


class TwoKeysForOneList(KitFileRefused):
    """An Illumina YAML file that gives two keys for one index list.

    ``i7Index1`` and ``Index1`` both name the i7 list (``i5Index2`` and
    ``Index2`` the i5 one). Reading the first and dropping the second lost
    every index in it without a word.
    """

    reason = "two_keys_for_one_list"


class KitModeDiffers(KitFileRefused):
    """A file whose ``index_mode`` is not the mode picked on the upload form.

    The form's picker always won and the file's key was never read, so a file
    saying ``combinatorial``, uploaded as Single, was stored as a Single kit
    with no word -- and every sample then took an i7 alone.
    """

    reason = "kit_mode_differs"


class KitNamesNothing(KitFileRefused):
    """A kit file that names neither the kit nor its version, uploaded with
    the matching box empty.

    A kit's name and version are its identity: the stored id, the address of
    its page, its download and its Delete, and what a sync compares between
    runs. The file's own name was used instead ("my_kit_file.csv" became the
    kit "my_kit_file"), and the version "1.0" was invented, so a kit was
    stored under a name nobody wrote.
    """

    reason = "kit_names_nothing"


_UNPAIRED_SHOWN = 10
_NAME_SHOWN = 40


def _quoted(name) -> str:
    """A name for a message. A hidden character is shown by its code, never
    itself: two names that differ only by one looked alike in the message,
    and a direction override would reorder the page around it (review
    leftover O6)."""
    text = str(name)
    hidden = hidden_characters(text)
    shown = text[:_NAME_SHOWN]
    for c in hidden:
        shown = shown.replace(c, f"<U+{ord(c):04X}>")
    quoted = f"'{shown}…'" if len(text) > _NAME_SHOWN else f"'{shown}'"
    return f"{quoted} (holds a hidden character: {describe(hidden)})" if hidden else quoted


def _names(names: list) -> str:
    shown = ", ".join(_quoted(name) for name in names[:_UNPAIRED_SHOWN])
    more = len(names) - _UNPAIRED_SHOWN
    return f"{shown} and {more} more" if more > 0 else shown


class ColumnsNotRead(KitFileRefused):
    """A kit file with a column whose name looks like an index or a lane but
    is not one the parser reads, or a row with a cell under no column name.

    Such a column was ignored: a file whose i5 column is called "Index 2"
    uploaded as Single dropped the i5 and said nothing. The sample paste has
    refused an unread index-looking column by name since 32ae40e.
    """

    reason = "columns_not_read"


class ListsNotRead(KitFileRefused):
    """A SeqSetup-format kit file holding an index list the chosen mode does
    not read. Such a list was kept in the kit where the index panel never
    shows it -- an index in the file that no sample can be given."""

    reason = "lists_not_read"


_LINES_SHOWN = 10

# Which of the three index lists each mode reads; the index panel shows only
# those, so a list a mode does not read is an index nothing can reach.
_INDEX_LISTS = ("index_pairs", "i7_indexes", "i5_indexes")
_LISTS_READ = {
    IndexMode.UNIQUE_DUAL: ("index_pairs",),
    IndexMode.COMBINATORIAL: ("i7_indexes", "i5_indexes"),
    IndexMode.SINGLE: ("i7_indexes",),
}

# The names the simple CSV reader looks for, in the order it looks (the
# lookups below are built from these, so a name added here is read).
_CSV_NAME_COLUMNS = ("name", "Name", "Sample_ID", "sample_id")
_CSV_I7_NAME_COLUMNS = ("i7_name", "I7_Name", "i7_index_name")
_CSV_I5_NAME_COLUMNS = ("i5_name", "I5_Name", "i5_index_name")
_CSV_I7_COLUMNS = ("index", "Index", "i7", "Index1", "index1", "sequence", "Sequence")
_CSV_I5_COLUMNS = ("index2", "Index2", "i5", "Index_2")
_CSV_WELL_COLUMNS = ("well", "Well", "well_position", "Well_Position")
_SIMPLE_CSV_COLUMNS = frozenset(
    _CSV_NAME_COLUMNS + _CSV_I7_NAME_COLUMNS + _CSV_I5_NAME_COLUMNS
    + _CSV_I7_COLUMNS + _CSV_I5_COLUMNS + _CSV_WELL_COLUMNS)
_SECTION_CSV_COLUMNS = frozenset(("name", "Name", "sequence", "Sequence") + _CSV_WELL_COLUMNS)
_SIMPLE_CSV_READS = ("name, index (the i7), index2 (the i5), i7_name, i5_name and "
                     "well_position")
_SECTION_CSV_READS = "name, sequence and well_position"

# Same rule as services/sample_parser.py: a header name holding "index" or
# "barcode", or a word starting i7, i5 or lane, is about an index or a lane.
_INDEX_OR_LANE_TEXT = ("index", "barcode")
_INDEX_OR_LANE_WORD = re.compile(r"^(i7|i5|lane)")
# A column called sequence2 or seq_2 is an i5 nobody reads: the simple CSV
# reads "sequence" as the i7 and has no such name for the i5, so the column
# was ignored and the i5 went nowhere (fresh review of a382f57, P2-3). Plain
# "sequence" stays a column the section CSV reads.
_SEQUENCE_WITH_A_NUMBER = re.compile(r"^seq(uence)?[\s_]*[0-9]")

# A cell of four or more bases is a sequence, so the line carrying it is an
# index line and not a section header however the header is spelled.
_LOOKS_LIKE_DNA = re.compile(r"^[ACGTN]{4,}\Z")


def _section_marker(line: str) -> Optional[str]:
    """``[i7]`` or ``[i5]`` when the line is that section's marker, else None.

    A spreadsheet writes the marker as ``[i7],`` or ``"[i7]"`` when the sheet
    has more than one column, and comparing the line with "[i7]" then read the
    marker as a line of the section (review of 14b7f6d).
    """
    bare = line.strip().strip('",').strip().lower()
    return bare if bare in ("[i7]", "[i5]") else None

_SINGLE_ADVICE = ("Upload the kit as Unique Dual (each i7 paired with the i5 of the same "
                  "name) or as Combinatorial (any i7 with any i5), or take the i5 data "
                  "out of the file.")


def _lines(numbers: list[int]) -> str:
    shown = ", ".join(f"line {n}" for n in numbers[:_LINES_SHOWN])
    more = len(numbers) - _LINES_SHOWN
    return f"{shown} and {more} more" if more > 0 else shown


def _looks_like_index_or_lane(name: str) -> bool:
    name = name.lower()
    return (any(text in name for text in _INDEX_OR_LANE_TEXT)
            or _SEQUENCE_WITH_A_NUMBER.match(name.strip())
            or any(_INDEX_OR_LANE_WORD.match(word) for word in re.split(r"[^a-z0-9]+", name)))


def _columns_not_read(header, read: frozenset, reads: str) -> None:
    """Refuse a header that this format cannot read as it stands.

    Two faults: a column whose name looks like an index or a lane but is not
    one the reader looks for (it was ignored without a word), and two columns
    whose normal form is the same, which would both be one slot -- the reader
    takes one of them and the other's sequences go nowhere.
    """
    names = [name for name in header or [] if name]
    read_keys = {_column_key(name) for name in read}
    unread = [name for name in names
              if _column_key(name) not in read_keys and _looks_like_index_or_lane(name)]
    if unread:
        quoted = ", ".join(f'"{name}"' for name in unread)
        raise ColumnsNotRead(
            f"The file has a column named {quoted}, which looks like an index or a lane "
            f"but is not a column this format reads, so nothing was saved: it would have "
            f"been ignored without a word. This format reads {reads}. Rename the column "
            f"or take it out."
        )
    # Two names for one slot: the reader takes the first alias it finds
    # (``_cell``) and the other's values go nowhere -- "name" beside
    # "Sample_ID", "index" beside "sequence" (fresh review of a382f57, P2-3).
    # The same-slot case covers the same-normal-form one, which
    # ``input_rules.table.refuse_repeated_columns`` also refuses first for a
    # header it read itself.
    seen: dict[str, str] = {}
    for name in names:
        key = _slot_key(name) or _column_key(name)
        # No name ("", " ", "_"): its cells are under no column name, which
        # _cells_with_no_column refuses when they hold anything (third fresh
        # review of the P2 fixes).
        if not key:
            continue
        if key in seen and seen[key] != name:
            raise ColumnsNotRead(
                f'The file has two columns, "{seen[key]}" and "{name}", that name one '
                f"column of this format, so nothing was saved: the reader would take one "
                f"of them and the other's values would go nowhere. Keep one."
            )
        seen[key] = name


# Which slot each name the readers look for fills, so a header naming one
# slot twice is seen.
_SLOTS = {
    "name": _CSV_NAME_COLUMNS + ("name", "Name"),
    "i7_name": _CSV_I7_NAME_COLUMNS,
    "i5_name": _CSV_I5_NAME_COLUMNS,
    "i7": _CSV_I7_COLUMNS + ("sequence", "Sequence"),
    "i5": _CSV_I5_COLUMNS,
    "well": _CSV_WELL_COLUMNS,
}


def _slot_key(name) -> Optional[str]:
    """The slot ``name`` fills, or None when no reader looks for it."""
    key = _column_key(name)
    for slot, names in _SLOTS.items():
        if key in {_column_key(known) for known in names}:
            return slot
    return None


def _cells_with_no_column(numbered) -> None:
    """Refuse rows that carry a cell under no column name (more cells than the
    header, or a cell in a column whose header name is blank), naming their
    lines: that cell was dropped unseen."""
    bad = [lineno for lineno, row in numbered
           if any(str(extra).strip() for extra in (row.get(None) or []))]
    if bad:
        raise ColumnsNotRead(
            f"These rows have a cell under no column name -- more cells than the header "
            f"has columns, or a cell in a column whose header name is blank or only spaces "
            f"and underscores -- so nothing was saved: {_lines(bad)}. Such a cell was "
            f"dropped unseen; give the column a header name or take the cell out."
        )


def _i5_in_single(where: str) -> I5DataInSingleKit:
    return I5DataInSingleKit(
        f"The file carries i5 data ({where}) but the kit was uploaded as Single, which "
        f"saves the i7 indexes only, so nothing was saved: the i5 data would have been "
        f"dropped without a word. {_SINGLE_ADVICE}"
    )


def _incomplete_csv_rows(numbers: list[int]) -> IncompleteIndexRows:
    return IncompleteIndexRows(
        f"These rows have content but no index name or no i7 sequence, so nothing was "
        f"saved: {_lines(numbers)}. Each row needs both (name,index[,index2]); a row "
        f"missing one was dropped without a word."
    )


def _column_key(name) -> str:
    """One normal form for a CSV column name: lower case, no spaces and no
    underscores, so ``INDEX``, ``Index`` and ``index_2`` read as the columns
    they plainly are. ``row.get("index")`` matched the header text exactly, so
    a file whose column said INDEX was read as having no i7 column at all --
    and then refused as an unread index-looking column.
    """
    return re.sub(r"[\s_]+", "", str(name).strip().lower())


def _by_column(row: dict) -> dict:
    """The row keyed by each column's normal form. The restkey (None) is kept
    under None so a cell with no column name is still found."""
    out = {}
    for name, value in row.items():
        out[None if name is None else _column_key(name)] = value
    return out


def _cell(row: dict, *names: str) -> str:
    """The first of ``names`` this CSV row has a value in, else "". ``names``
    are given as the reader writes them and compared by normal form."""
    keyed = _by_column(row)
    for name in names:
        value = keyed.get(_column_key(name))
        if value:
            return value
    return ""


def _csv_name(row: dict) -> str:
    return _cell(row, *_CSV_NAME_COLUMNS)


def _csv_i7(row: dict) -> str:
    return _cell(row, *_CSV_I7_COLUMNS)


def _csv_i5(row: dict) -> str:
    return _cell(row, *_CSV_I5_COLUMNS)


def _row_has_content(row: dict) -> bool:
    """True when any cell of the row holds something. A row with nothing in it
    is a blank line, not a dropped index."""
    # A row with more cells than the header puts the rest in one list under
    # the restkey: [""] is not content, and counting it as content refused a
    # row of only separators that used to upload (review of 3be7a45, P2-3).
    flat = []
    for value in row.values():
        flat.extend(value if isinstance(value, list) else [value])
    return any(str(value).strip() for value in flat if value)


def _text_or_refuse(data: dict) -> None:
    """Every index name and sequence in a SeqSetup-format file must be text.

    YAML reads an unquoted ``012`` as the number 10 and ``yes`` as true, so two
    names written differently could be read as one -- the same refusal the
    Illumina format already makes.
    """
    names_not_text: list = []
    sequences_not_text: list = []

    def check(entry, label: str) -> None:
        if not isinstance(entry, dict):
            return
        name = entry.get("name")
        if name is not None and not isinstance(name, str):
            names_not_text.append(name)
        sequence = entry.get("sequence")
        if sequence is not None and not isinstance(sequence, str):
            sequences_not_text.append(name if isinstance(name, str) else label)

    for pair in data.get("index_pairs") or []:
        if not isinstance(pair, dict):
            continue
        pair_name = pair.get("name")
        if pair_name is not None and not isinstance(pair_name, str):
            names_not_text.append(pair_name)
        check(pair.get("index1"), "an i7 in index_pairs")
        check(pair.get("index2"), "an i5 in index_pairs")
    for key, label in (("i7_indexes", "an i7 index"), ("i5_indexes", "an i5 index")):
        for entry in data.get(key) or []:
            check(entry, label)

    if names_not_text:
        raise IndexNamesNotText(
            f"YAML does not read these index names as text, so nothing was saved: it read "
            f"them as {_names(list(dict.fromkeys(names_not_text)))}. A name made only of "
            f"digits (012 is read as the number 10), or one of yes, no, true, false, on, "
            f"off or null, is not text to YAML. Put each such name in quotes, for example "
            f"name: '012'."
        )
    if sequences_not_text:
        raise IndexNamesNotText(
            f"These indexes have a sequence that is not text, so nothing was saved: "
            f"{_names(list(dict.fromkeys(sequences_not_text)))}. Write each sequence out, "
            f"for example sequence: ACGTACGT, and quote one YAML would read as a number."
        )


def _repeated(names: list) -> RepeatedNames:
    return RepeatedNames(
        f"The file gives {_names(list(dict.fromkeys(names)))} twice in one list, so nothing was saved: the "
        f"second would replace the first without a word. Give each index its own name."
    )


def _pairs_by_same_name(i7_indexes: dict, i5_indexes: dict) -> list[dict]:
    """Pair each i7 with the i5 of the same name, or raise UnpairedIndexes
    naming every index left without one. Nothing is guessed or dropped."""
    if i7_indexes and not i5_indexes:
        raise UnpairedIndexes(
            "The file has no i5 indexes, so it is not a Unique Dual kit and nothing was "
            "saved. If the kit is i7 only, upload it as Single; otherwise check the file's "
            "i5 list (i5Index2 in YAML, IndexNumber 2 in TSV)."
        )
    no_i5 = [name for name in i7_indexes if name not in i5_indexes]
    no_i7 = [name for name in i5_indexes if name not in i7_indexes]
    if no_i5 or no_i7:
        parts = ["The file's i7 and i5 indexes do not pair up by name, so nothing was saved. "
                 "In Unique Dual mode an i7 is paired only with the i5 of the same name."]
        if no_i5:
            parts.append(f"No i5 has the same name as these i7: {_names(no_i5)}.")
        if no_i7:
            parts.append(f"No i7 has the same name as these i5: {_names(no_i7)}.")
        parts.append("If any i7 may go with any i5, upload the kit as Combinatorial. For fixed "
                     "pairs, upload a CSV with each pair's i7 and i5 on one row (name,index,index2).")
        raise UnpairedIndexes(" ".join(parts))
    return [
        {"name": name,
         "index1": {"name": name, "sequence": seq},
         "index2": {"name": name, "sequence": i5_indexes[name]}}
        for name, seq in i7_indexes.items()
    ]


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


def _lists_in_mode(mode: IndexMode, i7: dict, i5: dict) -> dict:
    """The index lists a kit of ``mode`` holds, built from an Illumina YAML's
    or a TSV's two name-to-sequence maps, as each mode stored them."""
    if mode == IndexMode.COMBINATORIAL:
        return {"i7_indexes": [{"name": name, "sequence": seq} for name, seq in i7.items()],
                "i5_indexes": [{"name": name, "sequence": seq} for name, seq in i5.items()]}
    if mode == IndexMode.SINGLE:
        return {"i7_indexes": [{"name": name, "sequence": seq} for name, seq in i7.items()]}
    return {"index_pairs": _pairs_by_same_name(i7, i5)}


def _name_and_version(data: dict, name_key: str, version_key: str, default_name: str,
                      default_version: Optional[str], name_given: bool, version_given: bool,
                      where: str) -> dict:
    """The kit's name and version for the canonical map, refusing a file that
    names neither and an upload whose matching box is empty.

    The file's own value wins, as it does today: a pair's id is built from it,
    and the id is inside ``fingerprint()``, so the form's name overrides
    ``kit.name`` afterwards and no accepted file's fingerprint moves.
    ``name_given`` and ``version_given`` say whether the default came from a
    person -- the upload form's box -- or only from the file's own name.
    """
    said = {}
    for key, given, default, label, fix in (
        (name_key, name_given, default_name, "name", "the Kit name box"),
        (version_key, version_given, default_version, "version", "the Kit version box"),
    ):
        value = data.get(key) if key else None
        if value is not None and not (isinstance(value, str) and not value.strip()):
            said[label] = value
            continue
        if given:
            said[label] = default
            continue
        wrote = f"does not write {where.format(key=key)}" if key else f"carries no {label}"
        raise KitNamesNothing(
            f"The file {wrote} and {fix} is empty, so nothing was saved: a kit's "
            f"{label} is its identity -- the address of its page, its download and its "
            f"Delete, and what a configuration sync compares between runs. "
            + (f"Write the kit's {label} in the file or in {fix}."
               if key else f"This file format carries no {label}: fill in {fix}.")
        )
    return said


class IndexParser:
    """Read an index adapter kit file in any of the five shapes SeqSetup
    accepts, and check it against the one canonical kit rulebook
    (``input_rules/kits.py``). Each shape's own refusals -- a column not
    read, indexes that do not pair up, a list the mode does not read -- stay
    here, where the file's own words are."""

    @classmethod
    def _checked(cls, data: dict, locations: Locations, file: str,
                 index_mode: Optional[IndexMode] = None,
                 normalize: bool = False) -> IndexKit:
        """The kit a canonical map describes, checked by the rulebook.

        ``index_mode`` is the mode picked on the upload form, which wins as it
        does today; a file naming a different one is refused naming both,
        since a wrong mode decides which indexes a sample can be given.
        """
        if index_mode is not None:
            # A mode that is not the picked one is refused whatever kind of
            # value it is written as: a file saying index_mode: 3 had its
            # ValueError swallowed and the picked mode written in its place,
            # so the file was accepted where it was refused before (fresh
            # review of a382f57, P1-1). An empty value and null mean "names
            # none", as before.
            said = data.get("index_mode")
            if said is not None and said != "" and said != index_mode.value:
                raise KitModeDiffers(
                    f"The file says index_mode: {said!r} but the kit was uploaded as "
                    f"{index_mode.value}, so nothing was saved: the mode decides which "
                    f"indexes a sample can be given, and only one of the two can be right. "
                    f"Upload the kit in the mode its file says, or change the file."
                )
            data = {**data, "index_mode": index_mode.value}
        result = check_kit_data(data, locations, file)
        if not result.ok:
            raise KitFileProblems(result.problems, file)
        kit = build_kit(result.value)
        if normalize:
            # The upload has always written "1" as "1.0"; it is the builder's
            # business, after the check, and changing it would change the
            # stored identity of a kit a lab uploaded.
            kit.version = normalize_version(kit.version)
        return kit

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
        content = content.lstrip("\ufeff")

        if suffix in (".yaml", ".yml"):
            return cls._parse_yaml(content, file_path.stem, index_mode, file=file_path.name)
        elif suffix == ".tsv":
            return cls._parse_tsv(content, file_path.stem, index_mode, file=file_path.name)
        elif suffix == ".csv":
            return cls._parse_csv(content, file_path.stem, index_mode, file=file_path.name)
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

        # A spreadsheet writes UTF-8 with a byte order mark, which would hide
        # inside the first header name or the first section marker.
        content = content.lstrip("\ufeff")

        # A kit's name and version are its identity, so nothing invents one:
        # the file's own value wins, the form's box is next, and a file and a
        # box that both say nothing are refused (KitNamesNothing). The
        # filename's stem is still what a pair's id is built from when the
        # form names the kit, as it was before.
        default_name = kit_name or Path(filename).stem
        shape = dict(index_mode=index_mode, file=filename,
                     default_version=kit_version or "1.0",
                     name_given=bool(kit_name), version_given=bool(kit_version))

        if format_hint == "yaml":
            kit = cls._parse_yaml(content, default_name, **shape)
        elif format_hint == "tsv":
            kit = cls._parse_tsv(content, default_name, **shape)
        elif format_hint == "csv":
            kit = cls._parse_csv(content, default_name, **shape)
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
                safe_load_strict(content)
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
        file: str = "",
        default_version: Optional[str] = "1.0",
        name_given: bool = True,
        version_given: bool = True,
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
        read = read_yaml(content, file, values_safe=True)
        if read.problems:
            # A key given twice keeps today's words and its own audit
            # reason: in a kit file such a key is usually an index name, and
            # only the second entry was kept.
            twice = [p for p in read.problems if GIVEN_TWICE in p.message]
            if twice:
                raise RepeatedNames(
                    f"The file gives the key {_quoted(twice[0].path[-1])} twice in one "
                    f"section (line {twice[0].line}), so nothing was saved: the second "
                    f"would replace the first without a word."
                )
            raise KitFileProblems(read.problems, file)
        data = read.data

        if not data:
            raise ValueError("Empty or invalid YAML content")
        if not isinstance(data, dict):
            raise ValueError("A kit file holds a map of keys and values")

        # Detect format: sync format has "index_pairs" or "i7_indexes" keys
        is_sync_format = (
            "index_pairs" in data
            or "i7_indexes" in data
            or "index_mode" in data
        )

        if is_sync_format:
            return cls._parse_sync_yaml(data, read.locations, default_name, index_mode,
                                        file, default_version, name_given, version_given)
        return cls._parse_illumina_yaml(data, default_name, index_mode, file,
                                        default_version, name_given, version_given)

    @classmethod
    def _parse_sync_yaml(
        cls,
        data: dict,
        locations: Optional[Locations] = None,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
        file: str = "",
        default_version: Optional[str] = "1.0",
        name_given: bool = True,
        version_given: bool = True,
    ) -> IndexKit:
        """Read the canonical (SeqSetup) YAML shape: the keys are the
        rulebook's own, so the file's lines carry straight through."""
        locations = locations if locations is not None else Locations()
        _text_or_refuse(data)
        # The mode picked on the upload wins, as it does today; the file's
        # own key goes on into the canonical map so ``_checked`` can refuse a
        # file that names a different one.
        mode_str = data.get("index_mode", "unique_dual")
        try:
            file_mode = IndexMode(mode_str) if mode_str else IndexMode.UNIQUE_DUAL
        except ValueError:
            # Not a mode at all: the rulebook names the key and its line.
            if index_mode is None:
                return cls._checked(data, locations, file, None)
            file_mode = None
        mode = index_mode or file_mode

        # A Single kit saves single i7 indexes: its panel reads i7_indexes and
        # never the i5 list or the pairs, so either would have gone into a kit
        # that never shows them.
        if mode == IndexMode.SINGLE:
            if data.get("i5_indexes"):
                raise _i5_in_single("the file's i5_indexes list")
            if data.get("index_pairs"):
                raise PairsInSingleKit(
                    "The file lists index_pairs but the kit was uploaded as Single, which "
                    "hands out single i7 indexes and never reads the pairs, so nothing "
                    "was saved rather than every pair going unused and unseen. Upload the "
                    "kit as Unique Dual, or give the file an i7_indexes list."
                )
        # The other modes read their own lists too, and the panel shows only
        # those: a Combinatorial kit's pairs and a Unique Dual kit's i7 list
        # were kept where nothing ever shows them. The sync refuses every such
        # list (index_kit_sync_parser.KitListsNotRead); so does the upload
        # (review of 14b7f6d).
        read = _LISTS_READ[mode]
        unread = [key for key in _INDEX_LISTS if key not in read and data.get(key)]
        if unread:
            raise ListsNotRead(
                f"The kit was uploaded as {mode.value}, which reads "
                f"{' and '.join(read)}, so this file's {' and '.join(unread)} would have "
                f"been kept where the index panel never shows it and nothing was saved. "
                f"Upload the kit in the mode its lists are for, or take the unread "
                f"{'list' if len(unread) == 1 else 'lists'} out of the file."
            )

        said = _name_and_version(data, "name", "version", default_name, default_version,
                                 name_given, version_given, "a {key}")
        canonical = dict(data)
        canonical["name"] = said["name"]
        if said["version"] is not None:
            # Unchanged: str() + normalize_version ran before the check, so
            # version: 1 was stored as "1.0" on the upload while the sync
            # refused the same file (fresh review of a382f57, P2-2).
            canonical["version"] = said["version"]
        else:
            canonical.pop("version", None)
        # The file's own words when it wrote them, so a mode that is not the
        # one picked is seen; else the picked mode.
        # The file's own value whenever it wrote one, whatever kind it is,
        # so _checked can see a mode that is not the one picked; an empty
        # value and null mean "names none".
        canonical["index_mode"] = (data["index_mode"]
                                   if data.get("index_mode") not in (None, "")
                                   else mode.value)
        # An index2 that is empty or missing means an i7-only pair, as before.
        if isinstance(canonical.get("index_pairs"), list):
            canonical["index_pairs"] = [
                {key: value for key, value in pair.items() if not (key == "index2" and not value)}
                if isinstance(pair, dict) else pair
                for pair in canonical["index_pairs"]
            ]
        return cls._checked(canonical, locations, file, index_mode, normalize=True)

    @classmethod
    def _parse_illumina_yaml(
        cls,
        data: dict,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
        file: str = "",
        default_version: Optional[str] = "1.0",
        name_given: bool = True,
        version_given: bool = True,
    ) -> IndexKit:
        """Parse legacy Illumina YAML format."""
        # Parse index sequences
        index_seqs = data.get("IndexSequences", {})
        # ``a or b`` read one list and dropped the other without a word, so a
        # file that gives both keys is refused naming them. Only for a mapping:
        # anything else keeps the old behaviour (a generic parse failure).
        if isinstance(index_seqs, dict):
            for keys, label in ((("i7Index1", "Index1"), "i7"),
                                (("i5Index2", "Index2"), "i5")):
                given = [key for key in keys if key in index_seqs]
                if len(given) > 1:
                    raise TwoKeysForOneList(
                        f"The file's IndexSequences gives both '{given[0]}' and "
                        f"'{given[1]}' for its {label} list, so nothing was saved: one "
                        f"would be read and every index in the other dropped without a "
                        f"word. Keep one of the two keys."
                    )
        i7_indexes = index_seqs.get("i7Index1", {}) or index_seqs.get("Index1", {})
        i5_indexes = index_seqs.get("i5Index2", {}) or index_seqs.get("Index2", {})
        for label, keys, indexes in (("i7", "i7Index1 or Index1", i7_indexes),
                                     ("i5", "i5Index2 or Index2", i5_indexes)):
            if not isinstance(indexes, dict):
                raise IndexNamesNotText(
                    f"The file's {label} list ({keys}) is not written as name: sequence "
                    f"lines, so nothing was saved."
                )
            names_not_text = [name for name in indexes if not isinstance(name, str)]
            if names_not_text:
                raise IndexNamesNotText(
                    f"YAML does not read these {label} names as text, so nothing was saved: "
                    f"it read them as {_names(names_not_text)}. A name made only of digits "
                    f"(012 is read as the number 10), or one of yes, no, true, false, on, "
                    f"off or null, is not text to YAML. Put each such name in quotes, for "
                    f"example '012': ACGTACGT."
                )
            sequences_not_text = [name for name, seq in indexes.items() if not isinstance(seq, str)]
            if sequences_not_text:
                raise IndexNamesNotText(
                    f"These {label} indexes have a sequence that is empty or not text, so "
                    f"nothing was saved: {_names(sequences_not_text)}. Write each sequence "
                    f"out, for example A: ACGTACGT."
                )
        # A name with spaces around it is the same name to anyone reading the
        # panel, so it is kept without them and counts as a repeat.
        repeated: list[str] = []
        for indexes in (i7_indexes, i5_indexes):
            stripped: dict[str, str] = {}
            for name, seq in indexes.items():
                if name.strip() in stripped:
                    repeated.append(name.strip())
                stripped[name.strip()] = seq
            indexes.clear()
            indexes.update(stripped)
        if repeated:
            raise _repeated(repeated)

        # A Single kit saves the i7 indexes only, so an i5 list in the file
        # went nowhere. Checked against the mode as given, before the
        # auto-detect below overwrites it (a detected Single has no i5).
        if index_mode == IndexMode.SINGLE and i5_indexes:
            raise _i5_in_single("the file's i5Index2 list")

        # Auto-detect mode if not specified
        if index_mode is None:
            if not i5_indexes:
                index_mode = IndexMode.SINGLE
            else:
                index_mode = IndexMode.UNIQUE_DUAL

        said = _name_and_version(data, "Name", "Version", default_name, default_version,
                                 name_given, version_given, "a {key}:")
        canonical = {
            "name": said["name"],
            "index_mode": index_mode.value,
            **({"version": said["version"]} if said["version"] is not None else {}),
            **({"description": data["Description"]} if "Description" in data else {}),
            **_lists_in_mode(index_mode, i7_indexes, i5_indexes),
        }
        return cls._checked(canonical, Locations(), file, index_mode, normalize=True)

    @classmethod
    def _parse_tsv(
        cls,
        content: str,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
        file: str = "",
        default_version: Optional[str] = "1.0",
        name_given: bool = True,
        version_given: bool = True,
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
        lines = content.split("\n")
        current_section = None
        i7_indexes: dict[str, str] = {}
        i5_indexes: dict[str, str] = {}
        kit_name = None
        kit_version = None
        kit_description = None
        index_lines: dict = {}
        # An [IndexKit] line whose key is not one of the three read, or that
        # has one cell, was dropped without a word -- a real template's
        # AdapterRead1 vanished (fresh review of a382f57, P2-4).
        unread_settings: list[tuple[int, str]] = []
        repeated: list[str] = []
        incomplete: list[int] = []
        # The header line is only ever the section's first content line.
        seen_index_line = False
        # A line in no section, or under a section marker this format does not
        # read, had no branch at all and vanished while the file's other lines
        # kept the kit valid -- a section header spelled [Indexes] lost every
        # index under it with nothing said (review of 14b7f6d, P1-1).
        unread_sections: dict[str, list[int]] = {}

        for lineno, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue

            if line.startswith("["):
                current_section = line.strip("[]")
                seen_index_line = False
                continue

            parts = line.split("\t")

            if current_section == "IndexKit":
                key = parts[0].strip()
                if len(parts) >= 2 and key in ("Name", "Version", "Description"):
                    value = parts[1]
                    if key == "Name":
                        kit_name = value
                    elif key == "Version":
                        kit_version = value
                    else:
                        kit_description = value
                else:
                    unread_settings.append((lineno, key))

            elif current_section != "Indices":
                unread_sections.setdefault(
                    current_section if current_section is not None else "", []).append(lineno)

            else:
                cells = [part.strip() for part in parts]
                is_index_line = len(cells) >= 3 and cells[2] in ("1", "2")
                # The section's own first line is its header when it carries
                # no sequence, however it spells its columns ("IndexNumber",
                # "Index Number", or only Name and Sequence): matching one
                # exact spelling refused a file whose header read otherwise
                # (review of 3be7a45, P2-5).
                if not is_index_line and not seen_index_line and not any(
                        _LOOKS_LIKE_DNA.match(cell.upper()) for cell in cells):
                    seen_index_line = True
                    continue
                # A short line, or one whose index number is neither 1 nor 2,
                # was dropped without a word: the kit then held fewer indexes
                # than the file listed.
                if not is_index_line:
                    incomplete.append(lineno)
                    seen_index_line = True
                    continue
                seen_index_line = True
                name, seq, index_num = cells[0], cells[1], cells[2]
                if index_num == "1":
                    if name in i7_indexes:
                        repeated.append(name)
                    i7_indexes[name] = seq
                    index_lines[("i7", name)] = lineno
                else:
                    if name in i5_indexes:
                        repeated.append(name)
                    i5_indexes[name] = seq
                    index_lines[("i5", name)] = lineno

        if unread_sections:
            parts = []
            for section, numbers in unread_sections.items():
                where = f"[{section}]" if section else "no section (before the first one)"
                parts.append(f"{where}: {_lines(numbers)}")
            raise ColumnsNotRead(
                "These lines are in a part of the file this format does not read, so "
                "nothing was saved: " + "; ".join(parts) + ". This format reads an "
                "[IndexKit] section and an [Indices] section; a line anywhere else was "
                "dropped without a word, so a section marker spelled otherwise lost every "
                "index under it. Check the section's spelling, or take the lines out."
            )
        if unread_settings:
            named = ", ".join(f"line {n} ({key!r})" if key else f"line {n}"
                              for n, key in unread_settings[:_LINES_SHOWN])
            more = len(unread_settings) - _LINES_SHOWN
            raise ColumnsNotRead(
                f"These [IndexKit] lines are not one this format reads, so nothing was "
                f"saved: {named}{f' and {more} more' if more > 0 else ''}. An [IndexKit] "
                f"section holds a Name, a Version and a Description, each written as the "
                f"key, a tab and the value; any other line was dropped without a word. "
                f"Take the line out, or check the key's spelling."
            )
        if incomplete:
            raise IncompleteIndexRows(
                f"These [Indices] lines are not a name, a sequence and an index number "
                f"(1 for an i7, 2 for an i5), so nothing was saved: {_lines(incomplete)}. "
                f"Such a line was dropped without a word."
            )
        if repeated:
            raise _repeated(repeated)

        if index_mode == IndexMode.SINGLE and i5_indexes:
            raise _i5_in_single("its IndexNumber 2 lines")

        # Auto-detect mode if not specified
        if index_mode is None:
            if not i5_indexes:
                index_mode = IndexMode.SINGLE
            else:
                index_mode = IndexMode.UNIQUE_DUAL

        said = _name_and_version({"Name": kit_name, "Version": kit_version},
                                 "Name", "Version", default_name, default_version,
                                 name_given, version_given, "an [IndexKit] {key} line")
        canonical = {
            "name": said["name"],
            "index_mode": index_mode.value,
            **({"version": said["version"]} if said["version"] is not None else {}),
            **({"description": kit_description} if kit_description is not None else {}),
            **_lists_in_mode(index_mode, i7_indexes, i5_indexes),
        }
        locations = Locations()
        for slot, key in (("i7", "i7_indexes"), ("i5", "i5_indexes")):
            for n, entry in enumerate(canonical.get(key, [])):
                line = index_lines.get((slot, entry["name"]))
                if line:
                    for field in ("name", "sequence"):
                        locations.at((key, n, field), line)
        for n, pair in enumerate(canonical.get("index_pairs", [])):
            line = index_lines.get(("i7", pair["name"]))
            if line:
                locations.at(("index_pairs", n, "name"), line)
        return cls._checked(canonical, locations, file, index_mode)

    @classmethod
    def _parse_csv(
        cls,
        content: str,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
        file: str = "",
        default_version: Optional[str] = "1.0",
        name_given: bool = True,
        version_given: bool = True,
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
        # The strip is what lets DictReader find the header, but it also takes
        # lines off the front: count them so a refusal names the file's own
        # line, not the stripped content's.
        line_offset = content[:len(content) - len(content.lstrip())].count("\n")
        content = content.strip()

        # Check if this is combinatorial format (has [i7] section)
        if any(_section_marker(line) == "[i7]" for line in content.split("\n")):
            return cls._parse_combinatorial_csv(content, default_name, index_mode,
                                                line_offset=line_offset, file=file,
                                                default_version=default_version,
                                                name_given=name_given,
                                                version_given=version_given)

        # Parse simple format. The line number of each row comes with it: a row
        # with content but no name or no i7 sequence is refused by line, and
        # ``if name and i7_seq`` below dropped such a row without a word.
        table = read_table(content, line_offset)
        numbered = [(row.line, {**row.cells, None: row.extra}) for row in table.rows]
        rows = [row for _lineno, row in numbered]

        _columns_not_read(table.header, _SIMPLE_CSV_COLUMNS, _SIMPLE_CSV_READS)
        _cells_with_no_column(numbered)

        incomplete = [lineno for lineno, row in numbered
                      if _row_has_content(row) and not (_csv_name(row) and _csv_i7(row))]
        if incomplete:
            raise _incomplete_csv_rows(incomplete)

        # Check for i5 sequences to auto-detect mode
        has_i5 = any(_csv_i5(row) for row in rows)

        if index_mode == IndexMode.SINGLE and has_i5:
            raise _i5_in_single("the index2 column")

        # Auto-detect mode if not specified
        if index_mode is None:
            if not has_i5:
                index_mode = IndexMode.SINGLE
            else:
                index_mode = IndexMode.UNIQUE_DUAL

        said = _name_and_version({}, "", "", default_name, default_version,
                                 name_given, version_given, "")
        canonical: dict = {"name": said["name"], "index_mode": index_mode.value,
                           "version": said["version"]}
        locations = Locations()

        # Every column through the same lookups the checks above used, so a
        # header the check counted as read is a header the row is read by:
        # the two drifting apart is how an ignored column went unnoticed.
        pairs: list = []
        singles: list = []
        for lineno, row in numbered:
            name = _csv_name(row)
            i7_name = _cell(row, *_CSV_I7_NAME_COLUMNS) or name
            i5_name = _cell(row, *_CSV_I5_NAME_COLUMNS) or name
            i7_seq = _csv_i7(row)
            i5_seq = _csv_i5(row)
            well = _cell(row, *_CSV_WELL_COLUMNS) or None

            if name and i7_seq:
                if index_mode == IndexMode.SINGLE:
                    locations.at(("i7_indexes", len(singles), "name"), lineno)
                    locations.at(("i7_indexes", len(singles), "sequence"), lineno)
                    locations.at(("i7_indexes", len(singles), "well_position"), lineno)
                    singles.append({"name": name, "sequence": i7_seq, "well_position": well})
                else:
                    pair = {"name": name, "well_position": well,
                            "index1": {"name": i7_name, "sequence": i7_seq,
                                       "well_position": well}}
                    if i5_seq:
                        pair["index2"] = {"name": i5_name, "sequence": i5_seq,
                                          "well_position": well}
                    for field in ("name", "well_position"):
                        locations.at(("index_pairs", len(pairs), field), lineno)
                    for slot in ("index1", "index2"):
                        for field in ("name", "sequence", "well_position"):
                            locations.at(("index_pairs", len(pairs), slot, field), lineno)
                    pairs.append(pair)
        canonical["i7_indexes" if index_mode == IndexMode.SINGLE else "index_pairs"] = (
            singles if index_mode == IndexMode.SINGLE else pairs)
        return cls._checked(canonical, locations, file, index_mode)

    @classmethod
    def _parse_combinatorial_csv(
        cls,
        content: str,
        default_name: str = "Imported Kit",
        index_mode: Optional[IndexMode] = None,
        line_offset: int = 0,
        file: str = "",
        default_version: Optional[str] = "1.0",
        name_given: bool = True,
        version_given: bool = True,
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

        i7_entries: list = []
        i5_entries: list = []
        locations = Locations()

        lines = content.strip().split("\n")
        current_section = None
        # Each kept line with its own number, so a row with content but no name
        # or no sequence -- which ``if name and seq`` dropped without a word --
        # is refused by the line it is on.
        section_lines: list[tuple[int, str]] = []
        incomplete: list[int] = []
        outside: list[int] = []

        def process_section():
            nonlocal section_lines
            if not section_lines:
                return
            if current_section is None:
                # Lines before the first [i7] belong to no section. They were
                # kept and read as the next section's own, so an [IndexKit]
                # preamble became its header and the refusal named a good
                # index instead of the stray lines (review of 3be7a45, P2-4).
                outside.extend(lineno for lineno, _text in section_lines)
                section_lines = []
                return

            numbers = [lineno for lineno, _text in section_lines]
            try:
                table = read_table("\n".join(text for _n, text in section_lines))
            except TableNotRead as unread:
                # Its line counts this section's own lines; name the file's.
                raise type(unread)(numbers[min(unread.line, len(numbers)) - 1]) from None
            # A row's line_num counts the lines of this section read so far,
            # the header included, so it indexes the section's own line list.
            numbered = [(numbers[min(row.line, len(numbers)) - 1],
                         {**row.cells, None: row.extra}) for row in table.rows]
            _columns_not_read(table.header, _SECTION_CSV_COLUMNS, _SECTION_CSV_READS)
            _cells_with_no_column(numbered)

            for lineno, row in numbered:
                name = _cell(row, "name", "Name")
                seq = _cell(row, "sequence", "Sequence")
                well = _cell(row, *_CSV_WELL_COLUMNS) or None

                if not (name and seq):
                    if _row_has_content(row):
                        incomplete.append(lineno)
                    continue

                if current_section == "i7":
                    entries, key = i7_entries, "i7_indexes"
                elif current_section == "i5":
                    entries, key = i5_entries, "i5_indexes"
                else:
                    continue
                for field in ("name", "sequence", "well_position"):
                    locations.at((key, len(entries), field), lineno)
                entries.append({"name": name, "sequence": seq, "well_position": well})

            section_lines = []

        for lineno, line in enumerate(lines, start=1 + line_offset):
            line = line.strip()
            marker = _section_marker(line)

            if marker:
                process_section()
                current_section = marker.strip("[]")
            elif line:
                section_lines.append((lineno, line))

        # Process last section
        process_section()

        if outside:
            raise ColumnsNotRead(
                f"These lines are before the file's first [i7] section, so they belong to "
                f"no section and nothing was saved: {_lines(outside)}. An [i7] or [i5] "
                f"file holds only those two sections; such a line was read as part of the "
                f"next section or dropped."
            )
        if incomplete:
            raise _incomplete_csv_rows(incomplete)

        if index_mode == IndexMode.SINGLE and i5_entries:
            raise _i5_in_single("an [i5] section")

        # Last, as in _parse_csv: raised at the top it shadowed the
        # stray-line and repeated-column messages, so a file's real fault
        # was never said (fresh review of a382f57, P3-2).
        said = _name_and_version({}, "", "", default_name, default_version,
                                 name_given, version_given, "")
        canonical = {"name": said["name"], "index_mode": index_mode.value,
                     "version": said["version"], "i7_indexes": i7_entries}
        if index_mode != IndexMode.SINGLE:
            canonical["i5_indexes"] = i5_entries
        return cls._checked(canonical, locations, file, index_mode)
