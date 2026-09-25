"""Preview of a paste before it is added to a run.

Read-only. It shows what the parser read and flags rows for a person to
look at. It decides nothing about what is saved: POST /samples/bulk reads
the same text again and re-applies the one blocking rule (an ID repeated
within the paste) on its own.
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
        return not self.repeated_ids and self.to_add > 0 and not self.over_cap


def repeated_sample_ids(samples: list[ParsedSample]) -> list[str]:
    """Sample IDs that appear more than once, in first-seen order."""
    counts = Counter(s.sample_id for s in samples)
    return [sid for sid in dict.fromkeys(s.sample_id for s in samples) if counts[sid] > 1]


def _row_notes(s: ParsedSample, test: str, test_types: set[str]) -> list[str]:
    notes = []
    if test_types:
        if not test:
            notes.append("No test. Check will ask for one.")
        elif test not in test_types:
            note = f'No test called "{test}".'
            if _DNA_LIKE_RE.match(test.upper()):
                note += " It looks like an index sequence: is a column missing?"
            notes.append(note)
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
) -> PastePreview:
    """What the paste would add to a run holding ``existing_ids``.

    ``test_types`` are the known TestProfile test types (empty: no test
    checks, as Check does without profiles). ``default_test`` fills blank
    test cells only.
    """
    lines_by_id: dict[str, list[int]] = defaultdict(list)
    for s in read.samples:
        lines_by_id[s.sample_id].append(s.line)

    rows = []
    for s in read.samples:
        test = s.test_id or default_test
        others = [n for n in lines_by_id[s.sample_id] if n != s.line]
        if others:
            state = BLOCKED
            notes = [f"Same ID as line {', '.join(str(n) for n in others)}."]
        elif s.sample_id in existing_ids:
            state = SKIPPED
            notes = ["Already in this run. The one in the run is kept."]
        else:
            notes = _row_notes(s, test, test_types)
            state = LOOK if notes else OK
        rows.append(PreviewRow(
            line=s.line,
            sample_id=s.sample_id,
            test_id=test,
            test_picked=not s.test_id and bool(default_test),
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
    )
