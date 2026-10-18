"""Parse index adapter kit files in various formats."""

import csv
import re
from io import StringIO
from pathlib import Path
from typing import Optional

import yaml

from ..utils.yaml_safety import DuplicateKeyError, safe_load_strict, safe_load_unique_keys

from ..models.index import Index, IndexKit, IndexMode, IndexPair, IndexType


class KitFileRefused(ValueError):
    """A kit file refused for a fault of its own, which the upload route
    shows in full and audits under ``reason``."""

    reason = "kit_file_refused"


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


_UNPAIRED_SHOWN = 10
_NAME_SHOWN = 40


def _quoted(name) -> str:
    text = str(name)
    return f"'{text[:_NAME_SHOWN]}…'" if len(text) > _NAME_SHOWN else f"'{text}'"


def _names(names: list) -> str:
    shown = ", ".join(_quoted(name) for name in names[:_UNPAIRED_SHOWN])
    more = len(names) - _UNPAIRED_SHOWN
    return f"{shown} and {more} more" if more > 0 else shown


_LINES_SHOWN = 10

_SINGLE_ADVICE = ("Upload the kit as Unique Dual (each i7 paired with the i5 of the same "
                  "name) or as Combinatorial (any i7 with any i5), or take the i5 data "
                  "out of the file.")


def _lines(numbers: list[int]) -> str:
    shown = ", ".join(f"line {n}" for n in numbers[:_LINES_SHOWN])
    more = len(numbers) - _LINES_SHOWN
    return f"{shown} and {more} more" if more > 0 else shown


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


def _cell(row: dict, *names: str) -> str:
    """The first of ``names`` this CSV row has a value in, else ""."""
    for name in names:
        value = row.get(name)
        if value:
            return value
    return ""


def _csv_name(row: dict) -> str:
    return _cell(row, "name", "Name", "Sample_ID", "sample_id")


def _csv_i7(row: dict) -> str:
    return _cell(row, "index", "Index", "i7", "Index1", "index1", "sequence", "Sequence")


def _csv_i5(row: dict) -> str:
    return _cell(row, "index2", "Index2", "i5", "Index_2")


def _row_has_content(row: dict) -> bool:
    """True when any cell of the row holds something. A row with nothing in it
    is a blank line, not a dropped index."""
    return any(str(value).strip() for value in row.values() if value)


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


def _pairs_by_same_name(kit_name: str, i7_indexes: dict, i5_indexes: dict) -> list[IndexPair]:
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
        IndexPair(
            id=f"{kit_name}_{name}",
            name=name,
            index1=Index(name=name, sequence=seq, index_type=IndexType.I7),
            index2=Index(name=name, sequence=i5_indexes[name], index_type=IndexType.I5),
        )
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
        try:
            data = safe_load_unique_keys(content)
        except DuplicateKeyError as repeated:
            raise RepeatedNames(
                f"The file gives the key {_quoted(repeated.key)} twice in one section "
                f"(line {repeated.line}), so nothing was saved: the second would replace "
                f"the first without a word."
            ) from None

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
        _text_or_refuse(data)
        # Get index mode from file or parameter
        mode_str = data.get("index_mode", "unique_dual")
        file_mode = IndexMode(mode_str) if mode_str else IndexMode.UNIQUE_DUAL
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
            kit.index_pairs.extend(_pairs_by_same_name(kit.name, i7_indexes, i5_indexes))

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
        lines = content.split("\n")
        current_section = None
        i7_indexes: dict[str, str] = {}
        i5_indexes: dict[str, str] = {}
        kit_name = default_name
        kit_version = "1.0"
        kit_description = ""
        repeated: list[str] = []
        incomplete: list[int] = []

        for lineno, line in enumerate(lines, start=1):
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
                cells = [part.strip() for part in parts]
                # The section's own header line, which carries no index.
                if len(cells) >= 3 and cells[2].lower() == "indexnumber":
                    continue
                # A short line, or one whose index number is neither 1 nor 2,
                # was dropped without a word: the kit then held fewer indexes
                # than the file listed.
                if len(cells) < 3 or cells[2] not in ("1", "2"):
                    incomplete.append(lineno)
                    continue
                name, seq, index_num = cells[0], cells[1], cells[2]
                if index_num == "1":
                    if name in i7_indexes:
                        repeated.append(name)
                    i7_indexes[name] = seq
                else:
                    if name in i5_indexes:
                        repeated.append(name)
                    i5_indexes[name] = seq

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
            kit.index_pairs.extend(_pairs_by_same_name(kit.name, i7_indexes, i5_indexes))

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
        # The strip is what lets DictReader find the header, but it also takes
        # lines off the front: count them so a refusal names the file's own
        # line, not the stripped content's.
        line_offset = content[:len(content) - len(content.lstrip())].count("\n")
        content = content.strip()

        # Check if this is combinatorial format (has [i7] section)
        if content.startswith("[i7]") or "\n[i7]" in content:
            return cls._parse_combinatorial_csv(content, default_name, index_mode,
                                                line_offset=line_offset)

        # Parse simple format. The line number of each row comes with it: a row
        # with content but no name or no i7 sequence is refused by line, and
        # ``if name and i7_seq`` below dropped such a row without a word.
        reader = csv.DictReader(StringIO(content))
        numbered = [(reader.line_num + line_offset, row) for row in reader]
        rows = [row for _lineno, row in numbered]

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
        line_offset: int = 0,
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
        # Each kept line with its own number, so a row with content but no name
        # or no sequence -- which ``if name and seq`` dropped without a word --
        # is refused by the line it is on.
        section_lines: list[tuple[int, str]] = []
        incomplete: list[int] = []

        def process_section():
            nonlocal section_lines
            if not section_lines or current_section is None:
                return

            numbers = [lineno for lineno, _text in section_lines]
            reader = csv.DictReader(StringIO("\n".join(text for _n, text in section_lines)))

            for row in reader:
                # line_num counts the lines of this section read so far, the
                # header included, so it indexes the section's own line list.
                lineno = numbers[min(reader.line_num, len(numbers)) - 1]
                name = _cell(row, "name", "Name")
                seq = _cell(row, "sequence", "Sequence")
                well = _cell(row, "well", "Well", "well_position", "Well_Position") or None

                if not (name and seq):
                    if _row_has_content(row):
                        incomplete.append(lineno)
                    continue

                if current_section == "i7":
                    kit.i7_indexes.append(
                        Index(name=name, sequence=seq, index_type=IndexType.I7, well_position=well)
                    )
                elif current_section == "i5":
                    kit.i5_indexes.append(
                        Index(name=name, sequence=seq, index_type=IndexType.I5, well_position=well)
                    )

            section_lines = []

        for lineno, line in enumerate(lines, start=1 + line_offset):
            line = line.strip()

            if line.lower() == "[i7]":
                process_section()
                current_section = "i7"
            elif line.lower() == "[i5]":
                process_section()
                current_section = "i5"
            elif line:
                section_lines.append((lineno, line))

        # Process last section
        process_section()

        if incomplete:
            raise _incomplete_csv_rows(incomplete)

        if index_mode == IndexMode.SINGLE and kit.i5_indexes:
            raise _i5_in_single("an [i5] section")

        return kit
