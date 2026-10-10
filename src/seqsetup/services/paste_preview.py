"""Preview of a paste before it is added to a run.

Read-only. It shows what the parser read and flags rows for a person to
look at. It decides nothing about what is saved: POST /samples/bulk reads
the same text again and re-applies the blocking rules (an ID repeated
within the paste; a version with no test; a picked test with no version) on
its own.
"""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .sample_parser import ParsedSample, PasteReadResult

OK, LOOK, SKIPPED, BLOCKED = "ok", "look", "skipped", "blocked"

# A test value made only of bases is most likely an index sequence read into
# the test column (a headerless paste with the test column left out).
_DNA_LIKE_RE = re.compile(r"^[ACGTN]{6,}\Z")


@dataclass
class PreviewRow:
    line: int
    sample_id: str
    test_id: str
    test_picked: bool  # test came from the "Test for rows without one" picker
    test_version: str
    version_picked: bool  # version came from the "Version for rows without one" box
    index1: str
    index2: str
    index_name: str
    state: str
    notes: list[str] = field(default_factory=list)


@dataclass
class PastePreview:
    rows: list[PreviewRow]
    columns_used: list[tuple[str, str]]
    columns_unused: list[str]
    guessed: bool  # no header row, and more than one column was read
    repeated_ids: list[str]
    room: int  # how many more samples the run can take
    versions_without_test: list[int] = field(default_factory=list)  # lines
    picked_tests_without_version: list[int] = field(default_factory=list)  # lines

    def _count(self, *states: str) -> int:
        return sum(1 for r in self.rows if r.state in states)

    @property
    def to_add(self) -> int:
        return self._count(OK, LOOK)

    @property
    def to_look(self) -> int:
        return self._count(LOOK)

    @property
    def skipped(self) -> int:
        return self._count(SKIPPED)

    @property
    def blocked(self) -> int:
        return self._count(BLOCKED)

    @property
    def over_cap(self) -> bool:
        return self.to_add > self.room

    @property
    def can_add(self) -> bool:
        return (not self.repeated_ids and not self.versions_without_test
                and not self.picked_tests_without_version
                and self.to_add > 0 and not self.over_cap)

    @property
    def versions_without_test_text(self) -> str:
        return version_needs_test_text(self.versions_without_test)

    @property
    def picked_tests_without_version_text(self) -> str:
        return picked_test_needs_version_text(self.picked_tests_without_version)


def repeated_sample_ids(samples: list[ParsedSample]) -> list[str]:
    """Sample IDs that appear more than once, in first-seen order."""
    counts = Counter(s.sample_id for s in samples)
    return [sid for sid in dict.fromkeys(s.sample_id for s in samples) if counts[sid] > 1]


def versions_without_test(samples: list[ParsedSample], default_test: str) -> list[int]:
    """The lines of rows with a version of their own and no test, none in
    the row and none picked: a test and its version are set together
    (spec 2026-10-07 group A4, §2)."""
    return [s.line for s in samples if s.test_version and not (s.test_id or default_test)]


def version_needs_test_text(lines: list[int]) -> str:
    return (f"Row(s) {', '.join(str(n) for n in lines)}: a test version needs a test. "
            f"Give the row a test, or pick one in Test for rows without one.")


def picked_tests_without_version(samples: list[ParsedSample], default_test: str,
                                 default_version: str) -> list[int]:
    """The lines of rows that take the picked test and have no version, none
    in the row and none in the box: a test and its version are set together
    (spec 2026-10-07 group A4, §2, decision 6)."""
    if not default_test or default_version:
        return []
    return [s.line for s in samples if not s.test_id and not s.test_version]


def picked_test_needs_version_text(lines: list[int]) -> str:
    return (f"Row(s) {', '.join(str(n) for n in lines)}: the picked test needs a version. "
            f"Fill in Version for rows without one, for example 1.")


def _row_notes(s: ParsedSample, test: str, version: str, test_types: set[str]) -> list[str]:
    notes = []
    if version and not test:
        notes.append("A test version needs a test.")
    elif test and not s.test_id and not version:
        notes.append("The picked test needs a version.")
    elif test_types:
        if not test:
            notes.append("No test. Check will ask for one.")
        elif test not in test_types:
            note = f'No test called "{test}".'
            if _DNA_LIKE_RE.match(test.upper()):
                note += " It looks like an index sequence: is a column missing?"
            notes.append(note)
        if test and not version:
            notes.append("No test version. Check will ask for one.")
    has_name = s.index_pair_name or s.index1_name or s.index2_name
    if has_name and not (s.index1_sequence or s.index2_sequence):
        notes.append("Index name but no sequences, so no index is set.")
    return notes


def build_paste_preview(
    read: PasteReadResult,
    existing_ids: set[str],
    test_types: set[str],
    default_test: str,
    room: int,
    default_version: str = "",
) -> PastePreview:
    """What the paste would add to a run holding ``existing_ids``.

    ``test_types`` are the known TestProfile test types (empty: no test
    checks, as Check does without profiles). ``default_test`` fills blank
    test cells only, and ``default_version`` blank version cells only.
    """
    lines_by_id: dict[str, list[int]] = defaultdict(list)
    for s in read.samples:
        lines_by_id[s.sample_id].append(s.line)

    # A row already in the run is skipped, never added, so the version
    # rules do not look at it (spec 2026-10-07 group A4, §2).
    to_add = [s for s in read.samples if s.sample_id not in existing_ids]
    rows = []
    for s in read.samples:
        test = s.test_id or default_test
        # The box's version goes only to a row with a test (decision 6).
        version = s.test_version or (default_version if test else "")
        others = [n for n in lines_by_id[s.sample_id] if n != s.line]
        if others:
            state = BLOCKED
            notes = [f"Same ID as line {', '.join(str(n) for n in others)}."]
        elif s.sample_id in existing_ids:
            state = SKIPPED
            notes = ["Already in this run. The one in the run is kept."]
        else:
            notes = _row_notes(s, test, version, test_types)
            state = LOOK if notes else OK
        rows.append(PreviewRow(
            line=s.line,
            sample_id=s.sample_id,
            test_id=test,
            test_picked=not s.test_id and bool(default_test),
            test_version=version,
            version_picked=not s.test_version and bool(default_version) and bool(test),
            index1=s.index1_sequence,
            index2=s.index2_sequence,
            index_name=s.index_pair_name or "/".join(n for n in (s.index1_name, s.index2_name) if n),
            state=state,
            notes=notes,
        ))

    return PastePreview(
        rows=rows,
        columns_used=read.columns_used,
        columns_unused=read.columns_unused,
        guessed=not read.header_found and len(read.columns_used) > 1,
        repeated_ids=repeated_sample_ids(read.samples),
        room=room,
        versions_without_test=versions_without_test(to_add, default_test),
        picked_tests_without_version=picked_tests_without_version(
            to_add, default_test, default_version),
    )
