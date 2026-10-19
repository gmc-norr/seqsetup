"""The one canonical rulebook for index kit files
(docs/design/2026-10-18-input-rules-design.md, "Step 3: index kit files, every
format").

Five file shapes reach ``IndexKit``: the SeqSetup YAML the sync reads and the
exporter writes, the legacy Illumina YAML, the Illumina TSV and two CSV
shapes. Each has its own adapter in ``services/index_parser.py``, which keeps
the refusals that are about its own format (a column not read, indexes that do
not pair up, a list the mode does not read), and every adapter produces the
canonical map this rulebook checks. ``build_kit`` then makes today's
``IndexKit`` from the checked value only.

A kit file holds no credential, so a message may quote the value it is about
(``values_safe``, cut at 60 characters in the reader).
"""

from typing import Annotated, Literal, Optional

from pydantic import AfterValidator, Field, StringConstraints

from ..models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from ..utils.names import is_dot_only
from .base import FilledText256, StrictRules, Text256, whole
from .check import CheckResult, Finding, check_data, check_yaml
from .problems import InputProblem, path_text
from .reader import GIVEN_TWICE, Locations

# How many indexes one list of a kit file may hold. Nothing bounded a kit's
# size: 20,000 pairs make a 4.72 MB BSON document from a 2.63 MB file
# (measured 2026-10-19), so the sync's 10 MB per-file cap would give about
# 18 MB -- over MongoDB's 16 MiB, and the stored synced kits are deleted
# before the new ones are written (github_sync.py). 20,000 is some fifty
# times the largest shipped kit (384 pairs).
KIT_LIST_MAX = 20_000
# A sequence this long is nonsense, and nothing reads the bound: it is a
# sanity cap. A run reads at most 600 index cycles (routes/runs.py), and
# IndexValidator holds a kit's default cycles to every index's length, so a
# kit whose indexes are longer than 600 bases can never state its cycles.
MOST_BASES = 1000
MOST_INDEX_CYCLES = 600

_OVERRIDE_ALPHABET = set("YIUN0123456789*")
_DNA = set("ACGTN")

# Which of the three index lists each mode reads; the index panel shows only
# those, so a list a mode does not read is an index nothing can reach. The
# same table as services/index_parser.py's _LISTS_READ, which the adapters
# use to refuse a file by its own format's words.
LISTS_READ = {
    "unique_dual": ("index_pairs",),
    "combinatorial": ("i7_indexes", "i5_indexes"),
    "single": ("i7_indexes",),
}
_ALL_LISTS = ("index_pairs", "i7_indexes", "i5_indexes")


def _dna(value: str) -> str:
    """The sequence as the model stores it: uppercased and stripped (a YAML
    block scalar appends a newline, and a spreadsheet cell can carry spaces),
    then held to A, C, G, T and N."""
    sequence = value.upper().strip()
    if not sequence:
        raise ValueError("must hold a sequence")
    wrong = sorted(set(sequence) - _DNA)
    if wrong:
        raise ValueError(
            "may only hold A, C, G, T and N; it holds " + ", ".join(repr(c) for c in wrong))
    return sequence


def _id_text(value: str) -> str:
    """A name or version that can be carried in a kit's own URL. The version
    is the last path segment of the kit's page, download and Delete, and the
    stored ``_id`` is ``name:version``."""
    if ":" in value:
        raise ValueError("may not hold a ':': the stored id of a kit is its name and version, "
                         "joined by one")
    if "/" in value:
        raise ValueError("may not hold a '/': it is the last part of the kit's own address")
    if is_dot_only(value):
        raise ValueError("may not be made only of dots: a kit named so has no address")
    return value


def _no_dot_only_part(value: str) -> str:
    """A kit name may hold a '/' -- the shipped "IDT for Illumina DNA/RNA UD
    Indexes Set A" does -- so every part between slashes follows the rule
    (models/index.py)."""
    if any(is_dot_only(part) for part in value.split("/")):
        raise ValueError("may not have a part made only of dots: a kit named so has no address")
    return value


def _override_pattern(value: str) -> str:
    upper = value.upper()
    wrong = sorted(set(upper) - _OVERRIDE_ALPHABET)
    if wrong:
        raise ValueError(
            "may only hold Y, I, U, N, digits and '*'; it holds "
            + ", ".join(repr(c) for c in wrong))
    return upper


KitName = Annotated[FilledText256, AfterValidator(_no_dot_only_part)]
KitVersion = Annotated[FilledText256, AfterValidator(_id_text)]
KitDna = Annotated[str, StringConstraints(min_length=1, max_length=MOST_BASES),
                   AfterValidator(_dna)]
OverridePattern = Annotated[Text256, AfterValidator(_override_pattern)]
KitLabel = Annotated[str, StringConstraints(max_length=256)]
IndexCycles = whole(1, MOST_INDEX_CYCLES)


def _list_of(rules):
    return Annotated[list[rules], Field(max_length=KIT_LIST_MAX)]


class IndexRules(StrictRules):
    """One index in a kit's list, or one half of a pair."""

    name: FilledText256
    sequence: KitDna
    well_position: Optional[Text256] = None


class IndexPairRules(StrictRules):
    """One pre-paired i7 and i5. ``index2`` is absent for an i7-only pair."""

    name: FilledText256
    index1: IndexRules
    index2: Optional[IndexRules] = None
    well_position: Optional[Text256] = None


class KitRules(StrictRules):
    """One index kit, whatever file shape it came from. Which lists must hold
    indexes depends on ``index_mode``, so that is a check of its own below."""

    name: KitName
    version: KitVersion
    index_mode: Literal["unique_dual", "combinatorial", "single"]
    description: KitLabel = ""
    comments: KitLabel = ""
    is_fixed_layout: bool = False
    adapter_read1: Optional[KitDna] = None
    adapter_read2: Optional[KitDna] = None
    default_index1_cycles: Optional[IndexCycles] = None
    default_index2_cycles: Optional[IndexCycles] = None
    default_read1_override: Optional[OverridePattern] = None
    default_read2_override: Optional[OverridePattern] = None
    index_pairs: _list_of(IndexPairRules) = []
    i7_indexes: _list_of(IndexRules) = []
    i5_indexes: _list_of(IndexRules) = []


def _kit_findings(value: KitRules) -> list[Finding]:
    """The rules that relate the mode to the lists: the lists the mode reads
    must hold indexes, and a list it does not read must be empty -- an index
    the index panel never shows is an index no sample can be given."""
    found = []
    read = LISTS_READ[value.index_mode]
    for key in read:
        if not getattr(value, key):
            found.append(Finding(
                (key,), f"must hold at least one index: index_mode is {value.index_mode}, "
                        f"which reads {' and '.join(read)}"))
    for key in _ALL_LISTS:
        if key not in read and getattr(value, key):
            found.append(Finding(
                (key,), f"is not read when index_mode is {value.index_mode}, which reads "
                        f"{' and '.join(read)}: the index panel would never show these "
                        f"indexes, so no sample could be given one. Give the file the mode "
                        f"its lists are for, or take this list out."))
    return found


def check_kit_data(data, locations: Locations, file: str) -> CheckResult:
    """Check a canonical kit map an adapter built, with the locations it
    knows (none for a shape with no lines of its own)."""
    return check_data(data, locations, file, KitRules, cross_checks=[_kit_findings])


def check_index_kit_file(text: str, file: str) -> CheckResult:
    """Check one SeqSetup-format kit file -- what the sync reads and what
    ``IndexKitYamlExporter`` writes."""
    return check_yaml(text, file, KitRules, cross_checks=[_kit_findings])


# The upload form's own boxes (templates/indexes/import.html), in plain words.
# A value typed there becomes the kit's identity or its stored text, so it
# follows the same rules as the file's keys: the model cut a 300-character Kit
# name to 256 and stored an 8,000-base adapter whole.
FORM_BOXES = {
    "kit_name": "Kit name",
    "kit_version": "Kit version",
    "kit_description": "Kit description",
    "comments": "Comments",
    "adapter_read1": "Adapter Read 1",
    "adapter_read2": "Adapter Read 2",
}


class FormBoxRules(StrictRules):
    """What the import form's boxes may hold. A box left empty is no value
    and is left out before the check."""

    kit_name: Optional[KitName] = None
    kit_version: Optional[KitVersion] = None
    kit_description: Optional[KitLabel] = None
    comments: Optional[KitLabel] = None
    adapter_read1: Optional[KitDna] = None
    adapter_read2: Optional[KitDna] = None


def check_form_boxes(**values) -> list[str]:
    """One sentence per box that breaks a rule, naming the box in plain
    words. An empty box is left out: it means the box was not filled in."""
    given = {key: value for key, value in values.items() if value}
    result = check_data(given, Locations(), "", FormBoxRules)
    return [f"{FORM_BOXES.get(str(problem.path[0]), 'The form')}: {problem.message}"
            for problem in result.problems if problem.level == "error"]


class KitFileRefused(ValueError):
    """A kit file refused for a fault of its own, which the upload route
    shows in full and audits under ``reason``. Each shape's own refusals
    derive from it in ``services/index_parser.py``; the rules' own is
    ``KitFileProblems`` below."""

    reason = "kit_file_refused"


class KitFileProblems(KitFileRefused):
    """A kit file the rules refuse: ``problems`` has each one with its line,
    and ``reason`` is what the upload audits. The upload route shows every
    problem, where it once said "Failed to parse file" for all of them."""

    def __init__(self, problems: list[InputProblem], source_file: str = ""):
        self.problems = problems
        # The line first: a person fixing the file looks there, and the
        # sync's refusal and the upload's list are read as sentences.
        self.errors = [f"line {p.line}: {path_text(p.path)}: {p.message}"
                       for p in problems if p.level == "error"]
        self.source_file = source_file
        # A repeated index name is audited under repeated_names, and the
        # reader is what finds it now.
        self.reason = ("repeated_names"
                       if any(GIVEN_TWICE in p.message for p in problems)
                       else "kit_file_problems")
        where = f" in {source_file}" if source_file else ""
        super().__init__(f"This file was not saved{where}: " + "; ".join(self.errors))

    reason = "kit_file_problems"


def _index(value: IndexRules, index_type: IndexType) -> Index:
    return Index(name=value.name, sequence=value.sequence, index_type=index_type,
                 well_position=value.well_position)


def build_kit(value: KitRules, kit_name: Optional[str] = None,
              kit_version: Optional[str] = None, kit_description: Optional[str] = None,
              created_by: str = "", source: str = "user") -> IndexKit:
    """Today's ``IndexKit`` from the checked value only.

    ``kit_name``, ``kit_version`` and ``kit_description`` are the upload
    form's boxes, which win over the file's as they do today. A pair's ``id``
    keeps the name the **file** gave, as it does today: the ids are inside
    ``fingerprint()``, so taking the form's name would move the fingerprint of
    a file this release and the one before both accept.
    """
    kit = IndexKit(
        name=value.name,
        version=value.version,
        description=value.description,
        comments=value.comments,
        index_mode=IndexMode(value.index_mode),
        is_fixed_layout=value.is_fixed_layout,
        adapter_read1=value.adapter_read1,
        adapter_read2=value.adapter_read2,
        default_index1_cycles=value.default_index1_cycles,
        default_index2_cycles=value.default_index2_cycles,
        default_read1_override=value.default_read1_override,
        default_read2_override=value.default_read2_override,
        created_by=created_by,
        source=source,
    )
    kit.index_pairs = [
        IndexPair(
            id=f"{value.name}_{pair.name}",
            name=pair.name,
            index1=_index(pair.index1, IndexType.I7),
            index2=_index(pair.index2, IndexType.I5) if pair.index2 else None,
            well_position=pair.well_position,
        )
        for pair in value.index_pairs
    ]
    kit.i7_indexes = [_index(entry, IndexType.I7) for entry in value.i7_indexes]
    kit.i5_indexes = [_index(entry, IndexType.I5) for entry in value.i5_indexes]
    if kit_name:
        kit.name = kit_name
    if kit_version:
        kit.version = kit_version
    if kit_description:
        kit.description = kit_description
    return kit


def repeated_kit_versions(kits: list[IndexKit], paths: list[str]) -> list[str]:
    """Each kit name and version in more than one file: a sample's kit would
    be whichever was stored first. The sync has its own check, which also
    compares the kits already stored (``_refuse_changed_or_repeated_kits``);
    this is the half that needs no database, for the settings command."""
    files: dict[tuple, list[str]] = {}
    for kit, where in zip(kits, paths, strict=True):
        files.setdefault((kit.name, kit.version), []).append(where)
    problems = []
    for (name, version), names in files.items():
        if len(names) > 1:
            names = sorted(names)
            problems.append(f"{name} {version} is in {', '.join(names[:-1])} and {names[-1]}")
    return problems
