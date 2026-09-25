# Add Samples Preview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pasting samples shows a preview (what was read, which columns were used or dropped, a note per row) before anything is saved, and the paste box gets "Test for rows without one" and "Lanes" pickers.

**Architecture:** The server builds the preview with the same parser that saves (`read_pasted_samples`), through a pure read-only service (`build_paste_preview`). The preview's Add form carries the exact text back to `POST /samples/bulk`, which re-reads it and re-applies every blocking rule — the preview only shows, the bulk route decides.

**Tech Stack:** FastAPI, Jinja2, HTMX 2, Alpine.js (UI state only), Tailwind v4 + `components.css`, pytest (+ mongomock), Playwright.

Spec: `docs/superpowers/specs/2026-09-25-paste-preview-design.md`.

## Global Constraints

- Default lanes for pasted samples: lane 1 (ticked in the picker). At least one lane is required; an empty choice is rejected, never read as "all lanes".
- Repeated IDs: same ID twice in the paste → the whole paste is refused. ID already in the run → skipped and named.
- Default test fills only rows whose test cell is empty; it must be empty or a known `TestProfile.test_type`.
- Test checks in the preview only when at least one test profile exists.
- `/runs/{id}/samples/preview` and `/samples/bulk` use `Depends(get_editable_run)`; preview never mutates.
- Paste text cap 10 MB, UTF-8 files only (unchanged).
- Tests: `PYTHONPATH=src pixi run python -m pytest <file> -q` for one file; `pixi run test` for the whole server suite; `pixi run smoke-browser` for Playwright (builds CSS).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

---

### Task 1: Parser reports line numbers and columns

**Files:**
- Modify: `src/seqsetup/services/sample_parser.py`
- Test: `tests/unit/test_sample_parser.py` (append a class)

**Interfaces:**
- Produces: `ParsedSample.line: int` (1-based source line); `FIELD_LABELS: dict[str, str]`; `PasteReadResult(samples: list[ParsedSample], header_found: bool, columns_used: list[tuple[str, str]], columns_unused: list[str])`; `read_pasted_samples(paste_data: str) -> PasteReadResult`. `parse_pasted_samples(paste_data) -> list[ParsedSample]` unchanged in behaviour (returns `read_pasted_samples(...).samples`).

- [ ] **Step 1: Write the failing tests** — append to `tests/unit/test_sample_parser.py` (and add `read_pasted_samples` to its import line):

```python
class TestReadPastedSamples:
    """read_pasted_samples reports how it read the paste, so the preview can
    show guesses and dropped columns instead of hiding them."""

    def test_rows_carry_their_source_line(self):
        read = read_pasted_samples("sample_id,test_id\n\nS1,WGS\nS2,WGS\n")
        assert [(s.sample_id, s.line) for s in read.samples] == [("S1", 3), ("S2", 4)]

    def test_header_columns_used_and_unused(self):
        read = read_pasted_samples("sample_id\ttest_id\tlane\nS1\tWGS\t3\n")
        assert read.header_found is True
        assert read.columns_used == [("sample_id", "Sample ID"), ("test_id", "Test")]
        assert read.columns_unused == ["lane"]

    def test_empty_unknown_column_is_not_listed(self):
        assert read_pasted_samples("sample_id\tcomment\nS1\t\n").columns_unused == []

    def test_headerless_columns_are_guessed_by_position(self):
        read = read_pasted_samples("S1\tATTACTCG\tTATAGCCT\n")
        assert read.header_found is False
        assert read.columns_used == [
            ("column 1", "Sample ID"), ("column 2", "Test"), ("column 3", "i7"),
        ]
        assert read.samples[0].test_id == "ATTACTCG"  # the guess the preview must show

    def test_headerless_fifth_column_is_unused(self):
        assert read_pasted_samples("S1,WGS,ATTACTCG,TATAGCCT,extra\n").columns_unused == ["column 5"]

    def test_data_beyond_the_header_is_unused(self):
        assert read_pasted_samples("sample_id,test_id\nS1,WGS,surprise\n").columns_unused == ["column 3"]

    def test_parse_pasted_samples_still_returns_the_list(self):
        assert [s.sample_id for s in parse_pasted_samples("S1\nS2")] == ["S1", "S2"]

    def test_blank_input(self):
        read = read_pasted_samples("   ")
        assert (read.samples, read.header_found, read.columns_used, read.columns_unused) == ([], False, [], [])
```

- [ ] **Step 2: Run to see it fail**

Run: `PYTHONPATH=src pixi run python -m pytest tests/unit/test_sample_parser.py -q`
Expected: ImportError — `read_pasted_samples` does not exist.

- [ ] **Step 3: Implement** in `src/seqsetup/services/sample_parser.py`:

1. Add `line: int = 0  # 1-based line in the pasted text` as the last `ParsedSample` field.
2. After `INDEX2_NAME_HEADERS` add:

```python
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
```

3. Rename `def parse_pasted_samples(paste_data: str) -> list[ParsedSample]:` to `def read_pasted_samples(paste_data: str) -> PasteReadResult:` (keep its docstring, change "Returns: List of ParsedSample objects" to "Returns: PasteReadResult"). In its body:
   - the blank-input early return becomes `return PasteReadResult([], False, [], [])`;
   - the `ParsedSample(...)` call gains `line=source_line,`;
   - the final `return samples` becomes:

```python
    used, unused = _describe_columns(rows, header_detected, column_mapping)
    return PasteReadResult(samples, header_detected, used, unused)
```

4. Add the wrapper after it:

```python
def parse_pasted_samples(paste_data: str) -> list[ParsedSample]:
    """Parse pasted sample data; see read_pasted_samples."""
    return read_pasted_samples(paste_data).samples
```

- [ ] **Step 4: Run to see it pass**

Run: `PYTHONPATH=src pixi run python -m pytest tests/unit/test_sample_parser.py -q`
Expected: all pass (old tests included).

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/services/sample_parser.py tests/unit/test_sample_parser.py
git commit -m "feat(paste): parser reports source lines and which columns it used"
```

---

### Task 2: Preview service

**Files:**
- Create: `src/seqsetup/services/paste_preview.py`
- Test: `tests/unit/test_paste_preview.py`

**Interfaces:**
- Consumes: `PasteReadResult`, `ParsedSample.line` (Task 1).
- Produces: `repeated_sample_ids(samples) -> list[str]`; `build_paste_preview(read, existing_ids: set[str], test_types: set[str], default_test: str, room: int) -> PastePreview`; `PastePreview` fields `rows: list[PreviewRow]`, `columns_used`, `columns_unused`, `guessed: bool`, `repeated_ids: list[str]`, `room: int`; properties `to_add`, `to_look`, `skipped`, `blocked`, `over_cap`, `can_add`. `PreviewRow` fields `line, sample_id, test_id, test_picked, index1, index2, index_name, state ("ok"|"look"|"skipped"|"blocked"), notes: list[str]`.

- [ ] **Step 1: Write the failing tests** — `tests/unit/test_paste_preview.py`:

```python
"""The paste preview shows what a paste would add, before anything is saved.

It is read-only and decides nothing on its own: /samples/bulk re-reads the
same text and re-applies the blocking rule (a repeated ID).
"""

from seqsetup.services.paste_preview import build_paste_preview, repeated_sample_ids
from seqsetup.services.sample_parser import read_pasted_samples

HEADER = "sample_id\ttest_id\tindex_i7\tindex_i5\tindex_pair_name\n"


def _preview(text, *, existing=(), tests=("WGS",), default="", room=100):
    return build_paste_preview(read_pasted_samples(text), set(existing), set(tests), default, room)


class TestRowStates:
    """Each row is ok, look (can add), skipped (already in run) or blocked."""

    def test_clean_row_is_ok(self):
        row = _preview(HEADER + "S1\tWGS\tATTACTCG\tTATAGCCT\tUDP0001\n").rows[0]
        assert (row.state, row.notes, row.line) == ("ok", [], 2)
        assert (row.index1, row.index2, row.index_name) == ("ATTACTCG", "TATAGCCT", "UDP0001")

    def test_repeated_id_blocks_both_rows(self):
        p = _preview("S1,WGS\nS2,WGS\nS1,WGS\n")
        assert [r.state for r in p.rows] == ["blocked", "ok", "blocked"]
        assert p.rows[0].notes == ["Same ID as line 3."]
        assert p.repeated_ids == ["S1"]
        assert p.can_add is False

    def test_id_already_in_run_is_skipped(self):
        p = _preview("S1,WGS\nS2,WGS\n", existing={"S1"})
        assert p.rows[0].state == "skipped"
        assert (p.to_add, p.skipped, p.can_add) == (1, 1, True)

    def test_unknown_test_is_flagged(self):
        row = _preview("S1,WGX\n").rows[0]
        assert (row.state, row.notes) == ("look", ['No test called "WGX".'])

    def test_test_that_looks_like_dna_gets_a_hint(self):
        row = _preview("S1\tATTACTCG\tTATAGCCT\n").rows[0]
        assert "looks like an index sequence" in row.notes[0]

    def test_missing_test_is_flagged(self):
        assert _preview("S1\n").rows[0].notes == ["No test. Check will ask for one."]

    def test_no_test_checks_without_profiles(self):
        assert [r.state for r in _preview("S1\nS2,ANYTHING\n", tests=()).rows] == ["ok", "ok"]

    def test_index_name_without_sequence_is_flagged(self):
        row = _preview(HEADER + "S1\tWGS\t\t\tUDP0005\n").rows[0]
        assert row.notes == ["Index name but no sequences, so no index is set."]


class TestDefaultTest:
    """The picked test fills blank test cells only."""

    def test_fills_blank_tests_only(self):
        p = _preview("S1\nS2,RNA\n", tests=("WGS", "RNA"), default="WGS")
        assert [(r.test_id, r.test_picked) for r in p.rows] == [("WGS", True), ("RNA", False)]
        assert [r.state for r in p.rows] == ["ok", "ok"]


class TestSummary:
    """Counts, the guessed-columns flag and whether Add is allowed."""

    def test_guessed_only_when_headerless_with_several_columns(self):
        assert _preview("S1,WGS\n").guessed is True
        assert _preview("S1\n").guessed is False
        assert _preview("sample_id,test_id\nS1,WGS\n").guessed is False

    def test_counts(self):
        p = _preview("S1,WGS\nS2,WGX\nS3,WGS\n", existing={"S3"})
        assert (len(p.rows), p.to_add, p.to_look, p.skipped, p.blocked) == (3, 2, 1, 1, 0)

    def test_nothing_to_add_cannot_add(self):
        assert _preview("S1,WGS\n", existing={"S1"}).can_add is False

    def test_over_room_cannot_add(self):
        p = _preview("S1,WGS\nS2,WGS\n", room=1)
        assert (p.over_cap, p.can_add) == (True, False)


def test_repeated_sample_ids_keeps_first_seen_order():
    assert repeated_sample_ids(read_pasted_samples("B\nA\nB\nA\nC\n").samples) == ["B", "A"]
```

- [ ] **Step 2: Run to see it fail**

Run: `PYTHONPATH=src pixi run python -m pytest tests/unit/test_paste_preview.py -q`
Expected: ModuleNotFoundError `seqsetup.services.paste_preview`.

- [ ] **Step 3: Implement** — `src/seqsetup/services/paste_preview.py`:

```python
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
```

- [ ] **Step 4: Run to see it pass**

Run: `PYTHONPATH=src pixi run python -m pytest tests/unit/test_paste_preview.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/services/paste_preview.py tests/unit/test_paste_preview.py
git commit -m "feat(paste): read-only preview of what a paste would add"
```

---

### Task 3: Bulk add takes lanes and a default test; refuses repeated IDs

**Files:**
- Modify: `src/seqsetup/routes/samples.py` (imports; new `_PasteInput`, `_test_types`, `_read_paste_input`, `_name_list`, `_lane_words`; `add_bulk_samples`)
- Modify: `tests/integration/test_smoke_wizard.py` (two posts send `"lanes": "1"`)
- Modify: `tests/integration/test_sample_count_cap.py` (post sends `"lanes": "1"`)
- Create: `tests/integration/test_paste_preview.py`

**Interfaces:**
- Consumes: `parse_pasted_samples`, `repeated_sample_ids`.
- Produces (used by Task 4): `@dataclass _PasteInput(text: str, lanes: list[int], default_test: str, file_name: str = "")`; `async def _read_paste_input(request, run, ctx) -> tuple[_PasteInput | None, str]`; `def _test_types(ctx) -> set[str]`. Form fields: `paste_data`, `sample_file`, `lanes` (repeated), `default_test_id`.

- [ ] **Step 1: Write the failing tests** — `tests/integration/test_paste_preview.py`:

```python
"""Adding samples by paste: preview first, then add exactly what was shown.

The bulk route is the authority: it re-reads the text and refuses an ID
repeated within the paste, applies the picked lanes and the default test
(blank test cells only), and names IDs it skips because they are already
in the run.
"""

import html
import re

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.models.test_profile import TestProfile

ORIGIN = {"Origin": "http://testserver"}


def _run(ctx, run_id="paste-run", *, samples=(), status=RunStatus.DRAFT, flowcell="10B"):
    run = SequencingRun(
        id=run_id, run_name="Paste run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type=flowcell,
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    for s in samples:
        run.add_sample(s)
    ctx.run_repo.save(run)
    return run_id


def _wgs(ctx):
    ctx.test_profile_repo.save(TestProfile(test_type="WGS", test_name="Whole Genome"))


def _post(client, run_id, action, text, *, lanes=("1",), default_test=""):
    return client.post(
        f"/runs/{run_id}/samples/{action}",
        data={"paste_data": text, "lanes": list(lanes), "default_test_id": default_test},
        headers=ORIGIN,
    )


def _samples(ctx, run_id):
    return {s.sample_id: s for s in ctx.run_repo.get_by_id(run_id).samples}


class TestBulkAdd:
    """POST /samples/bulk applies lanes and the default test and refuses repeats."""

    def test_applies_lanes_and_default_test(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "bulk", "S1\nS2,RNA\n", lanes=("2", "3"), default_test="WGS")
        assert r.status_code == 200
        assert "Added 2 samples to lanes 2, 3." in r.text
        samples = _samples(ctx, run_id)
        assert (samples["S1"].lanes, samples["S1"].test_id) == ([2, 3], "WGS")
        assert (samples["S2"].lanes, samples["S2"].test_id) == ([2, 3], "RNA")

    def test_repeated_id_in_paste_adds_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "bulk", "S1,WGS\nS2,WGS\nS1,WGS\n")
        assert r.status_code == 200
        assert "more than once in the paste: S1" in r.text
        assert _samples(ctx, run_id) == {}

    def test_ids_already_in_run_are_skipped_and_named(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, samples=[Sample(id="old", sample_id="OLD-1", lanes=[1])])
        r = _post(logged_in_client, run_id, "bulk", "OLD-1,WGS\nNEW-1,WGS\n")
        assert "Skipped 1 already in the run: OLD-1." in r.text
        assert list(_samples(ctx, run_id)) == ["OLD-1", "NEW-1"]

    def test_no_lane_is_rejected(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = logged_in_client.post(f"/runs/{run_id}/samples/bulk", data={"paste_data": "S1,WGS"}, headers=ORIGIN)
        assert r.status_code == 400
        assert "at least one lane" in r.text
        assert _samples(ctx, run_id) == {}

    def test_lane_outside_flowcell_is_rejected(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "bulk", "S1,WGS", lanes=("9",))
        assert r.status_code == 400
        assert "between 1 and 8" in r.text

    def test_unknown_default_test_is_rejected(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "bulk", "S1", default_test="NOPE")
        assert r.status_code == 400
        assert "NOPE" in html.unescape(r.text)
        assert _samples(ctx, run_id) == {}

    def test_locked_run_is_forbidden(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, status=RunStatus.READY)
        assert _post(logged_in_client, run_id, "bulk", "S1,WGS").status_code == 403
```

- [ ] **Step 2: Run to see it fail**

Run: `PYTHONPATH=src pixi run python -m pytest tests/integration/test_paste_preview.py -q`
Expected: failures — lanes ignored (samples in lane 1), repeated IDs skipped instead of refused, no 400 for missing lanes.

- [ ] **Step 3: Implement** in `src/seqsetup/routes/samples.py`:

Imports: add `from dataclasses import dataclass`; change the parser import to `from ..services.sample_parser import parse_pasted_samples, read_pasted_samples`; add `from ..services.paste_preview import build_paste_preview, repeated_sample_ids`.

Add after `_normalize_lane_selection`:

```python
_MAX_PASTE_CHARS = 10 * 1024 * 1024


@dataclass
class _PasteInput:
    """What an Add-samples form sent: the text, and the picked lanes and test."""
    text: str
    lanes: list[int]
    default_test: str
    file_name: str = ""


def _test_types(ctx: AppContext) -> set[str]:
    repo = ctx.test_profile_repo
    return {tp.test_type for tp in repo.list_all()} if repo else set()


async def _read_paste_input(request: Request, run: SequencingRun, ctx: AppContext) -> tuple[Optional[_PasteInput], str]:
    """Read an Add-samples form (preview or add). Returns (input, "") or
    (None, message) for a 400. Saves nothing.

    Lanes: at least one, each within the flowcell — an empty choice is an
    error, never "all lanes". The default test must be empty or a known
    test profile.
    """
    form = await request.form()

    file_name = ""
    sample_file = form.get("sample_file")
    if sample_file and hasattr(sample_file, "read") and sample_file.filename:
        # Stream-read in bounded chunks so a multi-GB POST can't exhaust
        # memory before the size check fires.
        try:
            raw_bytes = await read_upload_capped(sample_file, _MAX_PASTE_CHARS)
        except UploadTooLargeError:
            return None, "File too large (max 10 MB)"
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None, "File must be UTF-8 encoded"
        file_name = sanitize_string(sample_file.filename, 256)
    else:
        text = form.get("paste_data", "")
        # Same cap as files: an unbounded paste could push the run document
        # past MongoDB's 16 MB limit on save.
        if len(text) > _MAX_PASTE_CHARS:
            return None, "Pasted data too large (max 10 MB)"

    max_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    lanes = _normalize_lane_selection(form.getlist("lanes"), max_lanes)
    if lanes is None:
        return None, f"Invalid lane selection. Use lane numbers between 1 and {max_lanes}."
    if not lanes:
        return None, "Pick at least one lane for the new samples."

    default_test = sanitize_string(form.get("default_test_id", ""), 256)
    if default_test and default_test not in _test_types(ctx):
        return None, f'No test called "{default_test}".'

    return _PasteInput(text=text, lanes=lanes, default_test=default_test, file_name=file_name), ""


def _name_list(ids: list[str], limit: int = 10) -> str:
    """'A, B, C' — the first ``limit`` names, then 'and N more'."""
    shown = ", ".join(ids[:limit])
    return f"{shown} and {len(ids) - limit} more" if len(ids) > limit else shown


def _lane_words(lanes: list[int]) -> str:
    return f"lane {lanes[0]}" if len(lanes) == 1 else "lanes " + ", ".join(str(n) for n in lanes)
```

Replace `add_bulk_samples` body from `form = await request.form()` down to the end with:

```python
    paste, error = await _read_paste_input(request, run, ctx)
    if paste is None:
        return Response(error, status_code=400)

    try:
        parsed = parse_pasted_samples(paste.text)
    except ValueError as e:
        # Reject the whole import — silent partial drops would land
        # patient samples in the Undetermined bucket. Surface the parse
        # error as a banner so the operator can fix the source and retry.
        return _render_sample_section(
            run, request, ctx,
            messages=[{"text": f"Bulk import rejected: {e}", "kind": "error"}],
        )

    # An ID twice in one paste: we can't tell which row is right, so the
    # whole paste is refused (the preview shows these rows in red).
    repeated = repeated_sample_ids(parsed)
    if repeated:
        return _render_sample_section(
            run, request, ctx,
            messages=[{
                "text": (
                    "Bulk import rejected: these sample IDs appear more than once "
                    f"in the paste: {_name_list(repeated)}. Nothing was added."
                ),
                "kind": "error",
            }],
        )

    existing_sample_ids = {s.sample_id for s in run.samples}
    skipped_duplicates: list[str] = []
    new_samples = []
    for ps in parsed:
        if ps.sample_id in existing_sample_ids:
            skipped_duplicates.append(ps.sample_id)
            continue
        sample = Sample(
            sample_id=ps.sample_id,
            test_id=ps.test_id or paste.default_test,
            lanes=list(paste.lanes),
        )

        if ps.index1_sequence:
            index1 = Index(
                name=ps.index1_name or "",
                sequence=ps.index1_sequence,
                index_type=IndexType.I7,
            )
            sample.assign_index1(index1)
            sample.index_kit_name = ps.index_pair_name or "Pasted"

        if ps.index2_sequence:
            index2 = Index(
                name=ps.index2_name or "",
                sequence=ps.index2_sequence,
                index_type=IndexType.I5,
            )
            sample.assign_index2(index2)
            if not sample.index_kit_name:
                sample.index_kit_name = ps.index_pair_name or "Pasted"

        _update_override_cycles(sample, run)
        new_samples.append(sample)
    added_count = len(new_samples)

    # Refuse before mutating if the additions would push the run past the
    # per-run cap (the model's add_sample backstop would otherwise raise
    # mid-loop and surface as a 500). Surface a clean banner instead.
    cap = sequencing_run_module.MAX_SAMPLES_PER_RUN
    if len(run.samples) + len(new_samples) > cap:
        return _render_sample_section(
            run, request, ctx,
            messages=[{
                "text": (
                    f"Bulk import rejected: a run accepts a maximum of {cap} "
                    f"samples (run already has {len(run.samples)})."
                ),
                "kind": "error",
            }],
        )

    if added_count > 0:
        with saving_run(run, ctx, request):
            for sample in new_samples:
                run.add_sample(sample)
        audit(
            "sample.bulk_added",
            actor=get_username(request),
            target=run_id,
            added_count=added_count,
            skipped_duplicates_count=len(skipped_duplicates),
            lanes=",".join(str(n) for n in paste.lanes),
            default_test_id=paste.default_test,
        )

    # Surface per-import feedback so skips are never silent.
    messages: list[dict] = []
    if added_count:
        noun = "sample" if added_count == 1 else "samples"
        messages.append({
            "text": f"Added {added_count} {noun} to {_lane_words(paste.lanes)}.",
            "kind": "success",
        })
    elif not parsed:
        messages.append({"text": "No samples found in input.", "kind": "warning"})
    if skipped_duplicates:
        messages.append({
            "text": (
                f"Skipped {len(skipped_duplicates)} already in the run: "
                f"{_name_list(skipped_duplicates)}."
            ),
            "kind": "warning",
        })

    return _render_sample_section(run, request, ctx, messages=messages or None)
```

(Keep the handler's `run_id = run.id` line at the top.)

Update the existing tests to send a lane:
- `tests/integration/test_smoke_wizard.py` — both `data={"paste_data": ...}` dicts in `TestBulkPasteSizeCap` become `data={"paste_data": ..., "lanes": "1"}`.
- `tests/integration/test_sample_count_cap.py` — `data={"paste_data": paste}` becomes `data={"paste_data": paste, "lanes": "1"}`.

- [ ] **Step 4: Run to see it pass**

Run: `PYTHONPATH=src pixi run python -m pytest tests/integration/test_paste_preview.py tests/integration/test_smoke_wizard.py tests/integration/test_sample_count_cap.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/seqsetup/routes/samples.py tests/integration/test_paste_preview.py tests/integration/test_smoke_wizard.py tests/integration/test_sample_count_cap.py
git commit -m "feat(paste): bulk add takes lanes and a default test; refuses repeated IDs"
```

---

### Task 4: Preview route, paste form and preview templates

**Files:**
- Modify: `src/seqsetup/routes/samples.py` (new `preview_paste` handler after `add_bulk_samples`)
- Create: `src/seqsetup/templates/runs/_paste_form.html`
- Create: `src/seqsetup/templates/runs/_paste_preview.html`
- Modify: `src/seqsetup/templates/runs/_sample_section.html:27-53` (form → `#paste-area` include)
- Modify: `src/seqsetup/static/css/components.css` (paste form + preview styles; focus ring list)
- Modify: `src/seqsetup/static/js/app.js` (`paste-all-lanes` action; actions get their element)
- Modify: `tests/integration/test_smoke_bootstrap.py:490` (form now posts to `/samples/preview`)
- Test: `tests/integration/test_paste_preview.py` (append), `tests/browser/test_paste_preview.py` (new)

**Interfaces:**
- Consumes: `_read_paste_input`, `_PasteInput`, `_test_types` (Task 3); `read_pasted_samples` (Task 1); `build_paste_preview`, `PastePreview` (Task 2).
- Produces: `POST /runs/{run_id}/samples/preview`; template contexts below.

- [ ] **Step 1: Write the failing tests** — append to `tests/integration/test_paste_preview.py`:

```python
def _add_form_text(page_html):
    m = re.search(r'<textarea name="paste_data" hidden>\n(.*?)</textarea>', page_html, re.S)
    return html.unescape(m.group(1)) if m else None


class TestPreviewRoute:
    """POST /samples/preview shows what would be added and saves nothing."""

    def test_preview_shows_rows_and_saves_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview", "sample_id,test_id,comment\nS1,WGS,hi\nS2,WGX,\n")
        assert r.status_code == 200
        assert "Check what we read" in r.text
        assert 'data-state="ok"' in r.text and 'data-state="look"' in r.text
        assert "Not used:" in r.text and "<code>comment</code>" in r.text
        assert "Add 2 samples" in r.text
        assert _samples(ctx, run_id) == {}

    def test_add_form_carries_the_exact_text(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        text = "\nS1,WGS\nS2,WGS"  # a leading blank line must survive the round trip
        r = _post(logged_in_client, run_id, "preview", text, lanes=("2",))
        assert _add_form_text(r.text) == text
        assert f'hx-post="/runs/{run_id}/samples/bulk"' in r.text
        assert '<input type="hidden" name="lanes" value="2">' in r.text

    def test_repeated_id_disables_add(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview", "S1,WGS\nS1,WGS\n")
        assert "Fix the red rows first." in r.text
        assert "/samples/bulk" not in r.text

    def test_unreadable_paste_shows_the_reason(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview", "sample_id,test_id\n,WGS\n")
        assert r.status_code == 200
        assert "sample_id is required" in r.text
        assert "/samples/bulk" not in r.text

    def test_guessed_columns_are_announced(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview", "S1\tATTACTCG\tTATAGCCT\n")
        assert "No header row, so we guessed the columns." in r.text

    def test_form_is_refilled_for_back_to_edit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview", "S1", lanes=("2",), default_test="WGS")
        assert 'name="lanes" value="2" checked' in r.text
        assert 'name="lanes" value="1">' in r.text
        assert '<option value="WGS" selected>' in r.text

    def test_no_lane_is_400(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        assert _post(logged_in_client, run_id, "preview", "S1", lanes=()).status_code == 400

    def test_locked_run_is_forbidden(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, status=RunStatus.READY)
        assert _post(logged_in_client, run_id, "preview", "S1").status_code == 403


class TestRunPagePasteForm:
    """The run page's Add-samples box previews first and offers the pickers."""

    def test_form_posts_to_preview_with_lane_1_ticked(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert f'hx-post="/runs/{run_id}/samples/preview"' in page
        assert 'name="lanes" value="1" checked' in page
        assert 'name="lanes" value="8">' in page

    def test_single_lane_flowcell_sends_lane_1(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, flowcell="")
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert '<input type="hidden" name="lanes" value="1">' in page
        assert 'type="checkbox" name="lanes"' not in page
```

Browser test — `tests/browser/test_paste_preview.py`:

```python
"""Paste, preview, then add: nothing is saved until Add, and Add saves
exactly what the preview showed."""

import pytest
from playwright.sync_api import expect


def _open_paste(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    page.click("summary.paste-section-summary")


def _preview(page):
    with page.expect_response(lambda r: r.url.endswith("/samples/preview") and r.status == 200):
        page.click(".paste-form button[type=submit]")


@pytest.mark.browser
def test_preview_then_add(logged_in_page, base_url, app_ctx, mutable_run_id):
    page = logged_in_page
    _open_paste(page, base_url, mutable_run_id)
    page.fill("#paste_data", "sample_id,test_id\nNEW-01,\nNEW-02,WGS\n")
    page.select_option("#default_test_id", "WGS")
    page.check("input[name=lanes][value='3']")
    _preview(page)

    expect(page.locator(".paste-table tbody tr")).to_have_count(2)
    expect(page.locator(".paste-preview")).to_contain_text("(picked)")
    assert len(app_ctx.run_repo.get_by_id(mutable_run_id).samples) == 4  # nothing saved yet

    page.click("text=Add 2 samples")
    expect(page.locator("#error-banner")).to_contain_text("Added 2 samples to lanes 1, 3.")
    added = {s.sample_id: s for s in app_ctx.run_repo.get_by_id(mutable_run_id).samples}
    assert (added["NEW-01"].test_id, added["NEW-01"].lanes) == ("WGS", [1, 3])


@pytest.mark.browser
def test_back_to_edit_keeps_the_text(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    _open_paste(page, base_url, mutable_run_id)
    page.fill("#paste_data", "KEEP-01,WGS")
    _preview(page)
    page.click("text=Back to edit")
    expect(page.locator("#paste_data")).to_have_value("KEEP-01,WGS")


@pytest.mark.browser
def test_repeated_id_disables_add(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    _open_paste(page, base_url, mutable_run_id)
    page.fill("#paste_data", "DUP-01,WGS\nDUP-01,WGS")
    _preview(page)
    expect(page.locator(".paste-actions button.btn-primary")).to_be_disabled()
    expect(page.locator(".paste-actions")).to_contain_text("Fix the red rows first.")
```

In `tests/integration/test_smoke_bootstrap.py:490`, change the assertion to
`assert 'hx-post="/runs/{}/samples/preview"'.format(run.id) in response.text`.

- [ ] **Step 2: Run to see it fail**

Run: `PYTHONPATH=src pixi run python -m pytest tests/integration/test_paste_preview.py -q`
Expected: new classes fail (404 on `/samples/preview`, no picker on the page).

- [ ] **Step 3: Implement**

Route — add after `add_bulk_samples` in `src/seqsetup/routes/samples.py`:

```python
@router.post("/runs/{run_id}/samples/preview", response_class=HTMLResponse)
async def preview_paste(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/preview — show what a paste would add.

    Saves nothing. Reads with the same parser as /samples/bulk; the preview's
    Add form sends the same text back there, which re-applies every rule.
    """
    paste, error = await _read_paste_input(request, run, ctx)
    if paste is None:
        return Response(error, status_code=400)

    test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
    cap = sequencing_run_module.MAX_SAMPLES_PER_RUN
    preview, read_error = None, ""
    try:
        read = read_pasted_samples(paste.text)
    except ValueError as e:
        read_error = str(e)
    else:
        preview = build_paste_preview(
            read,
            existing_ids={s.sample_id for s in run.samples},
            test_types={tp.test_type for tp in test_profiles},
            default_test=paste.default_test,
            room=cap - len(run.samples),
        )

    return render(request, "runs/_paste_preview.html", {
        "run": run,
        "paste": paste,
        "preview": preview,
        "read_error": read_error,
        "line_count": len(paste.text.splitlines()),
        "cap": cap,
        "test_profiles": test_profiles,
        "num_lanes": get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type),
    })
```

`src/seqsetup/templates/runs/_paste_form.html`:

```html
{#
   Add-samples form: paste or file, test for blank rows, lanes. Preview
   swaps the preview into #paste-area; nothing is saved until the
   preview's Add button.

   Inputs:
     run:           SequencingRun
     test_profiles: list[TestProfile]
     num_lanes:     int
     paste:         _PasteInput | undefined — refills the form after a preview
#}
{% set chosen_lanes = paste.lanes if paste else [1] %}
{% set chosen_test = paste.default_test if paste else '' %}
<form class="paste-form"
      hx-post="/runs/{{ run.id }}/samples/preview"
      hx-target="#paste-area"
      hx-swap="innerHTML"
      hx-encoding="multipart/form-data">
    {% include "wizard/_sample_paste_format_help.html" %}
    <label for="paste_data" class="paste-label">Paste rows from a spreadsheet</label>
    <textarea name="paste_data" id="paste_data" class="paste-textarea" rows="6"
              placeholder="sample_id&#9;test_id&#9;index_i7&#9;index_i5&#10;Sample001&#9;WGS&#9;ATTACTCG&#9;TATAGCCT">
{{ paste.text if paste else '' }}</textarea>
    <p class="paste-hint">Safest: make the first row name the columns, like <code>sample_id, test_id, index_i7, index_i5</code>.</p>
    <div class="file-upload-row">
        <label for="sample_file" class="file-upload-label">Or a file (.csv, .tsv, .txt):</label>
        <input type="file" name="sample_file" id="sample_file" accept=".csv,.tsv,.txt" class="sample-file-input">
    </div>
    <div class="paste-options">
        <div class="paste-option">
            <label for="default_test_id" class="paste-option-label">Test for rows without one</label>
            <select name="default_test_id" id="default_test_id" class="paste-select">
                <option value="">Leave blank</option>
                {% for tp in test_profiles %}
                <option value="{{ tp.test_type }}"{% if tp.test_type == chosen_test %} selected{% endif %}>{{ tp.test_type }}{% if tp.test_name and tp.test_name != tp.test_type %} ({{ tp.test_name }}){% endif %}</option>
                {% endfor %}
            </select>
            <span class="paste-option-help">Rows that already have a test keep it.</span>
        </div>
        {% if num_lanes > 1 %}
        <fieldset class="paste-option">
            <legend class="paste-option-label">Lanes for these samples</legend>
            <div class="paste-lane-boxes">
                {% for lane in range(1, num_lanes + 1) %}
                <label class="paste-lane"><input type="checkbox" name="lanes" value="{{ lane }}"{% if lane in chosen_lanes %} checked{% endif %}> {{ lane }}</label>
                {% endfor %}
                <button type="button" class="paste-link" data-action="paste-all-lanes">All lanes</button>
            </div>
            <span class="paste-option-help">New samples start in lane 1. Change it here, or later in the table.</span>
        </fieldset>
        {% else %}
        <div class="paste-option">
            <span class="paste-option-label">Lane</span>
            <span>1</span>
            <input type="hidden" name="lanes" value="1">
        </div>
        {% endif %}
    </div>
    <div class="paste-buttons">
        <button type="submit" class="btn btn-primary">Preview</button>
        <button type="button" class="paste-link" data-action="clear-paste">Clear</button>
        <span class="paste-option-help">Nothing is saved until you press Add on the next screen.</span>
    </div>
</form>
```

`src/seqsetup/templates/runs/_paste_preview.html`:

```html
{#
   Add-samples preview: what the paste would add, before anything is saved.
   Swapped into #paste-area by POST /runs/{id}/samples/preview.

   The Add form carries the exact previewed text; /samples/bulk reads it
   again and re-applies every blocking rule, so this page shows, it never
   decides. Alpine only toggles between this preview and the refilled form.

   Inputs:
     run, test_profiles, num_lanes — as for runs/_paste_form.html
     paste:      _PasteInput — text, lanes, default_test, file_name
     preview:    PastePreview | None — None when the text could not be read
     read_error: str — the parser's message when preview is None
     line_count: int
     cap:        int — most samples a run may hold
#}
<div x-data="{ editing: false }">
    <div x-show="editing" x-cloak>
        {% include "runs/_paste_form.html" %}
    </div>
    <div x-show="!editing" class="paste-preview">
        <div class="paste-recap">
            <span>{% if paste.file_name %}File {{ paste.file_name }}{% else %}Pasted text, {{ line_count }} line{{ '' if line_count == 1 else 's' }}{% endif %}</span>
            <span>Test for blank rows: <b>{{ paste.default_test or 'leave blank' }}</b></span>
            <span>Lanes: <b>{{ paste.lanes | join(', ') }}</b></span>
            <button type="button" class="paste-link" @click="editing = true">Edit paste</button>
        </div>

        <h3 class="paste-preview-title">Check what we read</h3>

        {% if read_error %}
        <div class="paste-notice paste-notice--blocked" role="alert">
            <b>Can't read this paste.</b>
            <span>{{ read_error }}</span>
        </div>
        {% elif not preview.rows %}
        <div class="paste-notice paste-notice--look">No samples found in the paste.</div>
        {% else %}
            {% if preview.repeated_ids %}
            <div class="paste-notice paste-notice--blocked" role="alert">
                <b>Can't add yet.</b>
                <span>Same sample ID more than once in the paste: {{ preview.repeated_ids | join(', ') }}. We can't tell which row is right. Fix the paste, then preview again.</span>
            </div>
            {% endif %}
            {% if preview.over_cap %}
            <div class="paste-notice paste-notice--blocked" role="alert">
                <b>Too many samples.</b>
                <span>A run holds at most {{ cap }} samples. This run has {{ run.samples | length }}, and the paste would add {{ preview.to_add }}.</span>
            </div>
            {% endif %}
            {% if preview.guessed %}
            <div class="paste-notice paste-notice--look">
                <b>No header row, so we guessed the columns.</b>
                <span>{% for col, fld in preview.columns_used %}{{ col | capitalize }} = {{ fld }}{{ ', ' if not loop.last }}{% endfor %}. If that's wrong, add a first row that names the columns.</span>
            </div>
            {% endif %}

            <div class="paste-counts">
                <span class="paste-chip">{{ preview.rows | length }} sample{{ '' if preview.rows | length == 1 else 's' }} read</span>
                {% if preview.can_add %}<span class="paste-chip paste-chip--add">{{ preview.to_add }} will be added</span>{% endif %}
                {% if preview.skipped %}<span class="paste-chip paste-chip--skipped">{{ preview.skipped }} skipped</span>{% endif %}
                {% if preview.to_look %}<span class="paste-chip paste-chip--look">{{ preview.to_look }} to look at</span>{% endif %}
                {% if preview.blocked %}<span class="paste-chip paste-chip--blocked">{{ preview.blocked }} repeated</span>{% endif %}
            </div>

            <div class="paste-columns">
                <span class="paste-columns-label">Columns used:</span>
                {% for col, fld in preview.columns_used %}<span class="paste-col"><code>{{ col }}</code> → {{ fld }}</span>{% endfor %}
                {% if preview.columns_unused %}
                <span class="paste-columns-label">Not used:</span>
                {% for col in preview.columns_unused %}<span class="paste-col paste-col--unused"><code>{{ col }}</code></span>{% endfor %}
                {% endif %}
            </div>

            <div class="paste-table-wrap">
                <table class="paste-table">
                    <thead>
                        <tr>
                            <th scope="col">Line</th>
                            <th scope="col">Sample ID</th>
                            <th scope="col">Test</th>
                            <th scope="col">i7</th>
                            <th scope="col">i5</th>
                            <th scope="col">Index name</th>
                            <th scope="col">Lanes</th>
                            <th scope="col">Note</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for r in preview.rows %}
                        <tr class="paste-row paste-row--{{ r.state }}" data-state="{{ r.state }}">
                            <td>{{ r.line }}</td>
                            <td>{{ r.sample_id }}</td>
                            <td>{% if r.test_picked %}<i>{{ r.test_id }}</i> <span class="paste-picked">(picked)</span>{% else %}{{ r.test_id or '–' }}{% endif %}</td>
                            <td class="seq i7">{{ r.index1 or 'none' }}</td>
                            <td class="seq i5">{{ r.index2 or 'none' }}</td>
                            <td>{{ r.index_name }}</td>
                            <td>{{ '–' if r.state == 'skipped' else paste.lanes | join(', ') }}</td>
                            <td class="paste-note">
                                {%- if r.state == 'ok' %}OK
                                {%- else %}<b class="paste-badge paste-badge--{{ r.state }}">{% if r.state == 'blocked' %}Repeated{% elif r.state == 'skipped' %}Skipped{% else %}Look{% endif %}</b> {{ r.notes | join(' ') }}{% endif -%}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        {% endif %}

        <div class="paste-actions">
            {% if preview and preview.can_add %}
            <form hx-post="/runs/{{ run.id }}/samples/bulk"
                  hx-target="#sample-section"
                  hx-swap="outerHTML"
                  hx-disabled-elt="find button">
                <textarea name="paste_data" hidden>
{{ paste.text }}</textarea>
                {% for lane in paste.lanes %}<input type="hidden" name="lanes" value="{{ lane }}">{% endfor %}
                <input type="hidden" name="default_test_id" value="{{ paste.default_test }}">
                <button type="submit" class="btn btn-primary">Add {{ preview.to_add }} sample{{ '' if preview.to_add == 1 else 's' }}</button>
            </form>
            {% else %}
            <button type="button" class="btn btn-primary" disabled>Add samples</button>
            <span class="paste-blocked-hint">{% if read_error or (preview and (preview.repeated_ids or preview.over_cap)) %}Fix the red rows first.{% else %}Nothing to add.{% endif %}</span>
            {% endif %}
            <button type="button" class="paste-link" @click="editing = true">Back to edit</button>
            {% if preview and preview.can_add %}<span class="paste-option-help">Adds exactly what is shown here.</span>{% endif %}
        </div>
    </div>
</div>
```

`src/seqsetup/templates/runs/_sample_section.html` — replace the `<form …>…</form>` inside `.paste-section-content` with:

```html
                <div id="paste-area">
                    {% include "runs/_paste_form.html" %}
                </div>
```

(and add `test_profiles` / `num_lanes` usage note to its Inputs comment: "the paste form uses test_profiles and num_lanes").

`src/seqsetup/static/js/app.js`:
- add before `const _CLICK_ACTIONS`:

```javascript
function tickAllPasteLanes(el) {
    const form = el.closest('form');
    if (form) form.querySelectorAll('input[name="lanes"][type="checkbox"]').forEach(cb => { cb.checked = true; });
}
```

- add `'paste-all-lanes': tickAllPasteLanes,` to `_CLICK_ACTIONS`;
- in the click listener, `if (fn) { fn(); return; }` becomes `if (fn) { fn(actionEl); return; }`.

`src/seqsetup/static/css/components.css`:
- add `.paste-link:focus-visible, .paste-select:focus-visible,` to the focus-ring selector list (the rule containing `.paste-textarea:focus-visible`);
- `.paste-buttons` gains `align-items: center;`;
- append after `.paste-buttons { … }`:

```css
/* Add samples: paste form pickers + preview */
.paste-label, .paste-option-label { display: block; font-size: var(--fs-sm); font-weight: var(--fw-semibold); margin: var(--space-3) 0 var(--space-1); padding: 0; }
.paste-hint, .paste-option-help { font-size: var(--fs-xs); color: var(--text-muted); }
.paste-hint { margin: var(--space-1) 0 0; }
.paste-hint code, .paste-col code { font-family: var(--font-mono); }
.sample-file-input::file-selector-button { font: inherit; padding: var(--space-1) var(--space-3); margin-right: var(--space-2); border: 1px solid var(--border-strong); border-radius: var(--radius-sm); background: var(--surface); color: var(--text); cursor: pointer; }
.paste-options { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: var(--space-5); margin-top: var(--space-4); padding-top: var(--space-1); border-top: 1px solid var(--border); }
.paste-option { display: flex; flex-direction: column; gap: var(--space-1); border: 0; margin: 0; padding: 0; min-width: 0; }
.paste-select { max-width: 20rem; padding: var(--space-2); border: 1px solid var(--border-strong); border-radius: var(--radius-sm); background: var(--surface); font-size: var(--fs-sm); }
.paste-lane-boxes { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); }
.paste-lane { display: inline-flex; align-items: center; gap: var(--space-1); padding: var(--space-1) var(--space-2); border: 1px solid var(--border-strong); border-radius: var(--radius-sm); font-size: var(--fs-sm); cursor: pointer; }
.paste-lane:has(input:checked) { border-color: var(--primary); background: var(--info-bg); }
.paste-link { background: none; border: 0; padding: var(--space-1); color: var(--primary); text-decoration: underline; font-size: var(--fs-sm); cursor: pointer; }
.paste-link:hover { color: var(--primary-hover); }
.paste-preview { display: flex; flex-direction: column; gap: var(--space-3); }
.paste-recap { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-4); padding: var(--space-2) var(--space-3); background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: var(--fs-sm); color: var(--text-muted); }
.paste-recap b { color: var(--text); }
.paste-recap .paste-link { margin-left: auto; }
.paste-preview-title { margin: var(--space-1) 0 0; font-size: var(--fs-lg); font-weight: var(--fw-bold); }
.paste-notice { padding: var(--space-3); border: 1px solid; border-radius: var(--radius-sm); font-size: var(--fs-sm); }
.paste-notice b { display: block; }
.paste-notice--blocked { background: var(--danger-bg); color: var(--danger-fg); border-color: #fecaca; }
.paste-notice--look { background: var(--warning-bg); color: var(--warning-fg); border-color: #fde68a; }
.paste-counts, .paste-columns { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); font-size: var(--fs-xs); }
.paste-chip { padding: 2px var(--space-3); border: 1px solid var(--border); border-radius: var(--radius-pill); }
.paste-chip--add { background: var(--success-bg); color: var(--success-fg); border-color: #bbf7d0; font-weight: var(--fw-semibold); }
.paste-chip--skipped { background: var(--border); color: #334155; border-color: var(--border-strong); }
.paste-chip--look { background: var(--warning-bg); color: var(--warning-fg); border-color: #fde68a; }
.paste-chip--blocked { background: var(--danger-bg); color: var(--danger-fg); border-color: #fecaca; font-weight: var(--fw-semibold); }
.paste-columns-label { color: var(--text-muted); }
.paste-col { padding: 2px var(--space-2); background: var(--surface-sunken); border-radius: var(--radius-sm); }
.paste-col--unused { background: var(--warning-bg); color: var(--warning-fg); }
.paste-table-wrap { max-height: 28rem; overflow: auto; border: 1px solid var(--border); border-radius: var(--radius-sm); }
.paste-table { width: 100%; border-collapse: collapse; font-size: var(--fs-xs); }
.paste-table th { position: sticky; top: 0; padding: var(--space-2); background: var(--surface-sunken); color: #334155; text-align: left; }
.paste-table td { padding: var(--space-2); border-top: 1px solid var(--border); vertical-align: top; }
.paste-table .seq { font-family: var(--font-mono); }
.paste-table .seq.i7 { color: #1d4ed8; }
.paste-table .seq.i5 { color: #c2410c; }
.paste-row--look { background: #fffbeb; }
.paste-row--blocked { background: var(--danger-bg); }
.paste-row--skipped { background: var(--bg); color: var(--text-muted); }
.paste-row--skipped .seq { color: inherit; }
.paste-row--ok .paste-note { color: var(--success-fg); }
.paste-badge { display: inline-block; margin-right: var(--space-1); padding: 0 var(--space-1); border-radius: var(--radius-sm); font-weight: var(--fw-semibold); }
.paste-badge--look { background: var(--warning-bg); color: var(--warning-fg); border: 1px solid #fde68a; }
.paste-badge--blocked { background: #b91c1c; color: #fff; }
.paste-badge--skipped { background: var(--border); color: #334155; }
.paste-picked { color: var(--text-muted); font-size: var(--fs-2xs); }
.paste-actions { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-4); }
.paste-actions form { margin: 0; }
.paste-blocked-hint { color: var(--danger-fg); font-size: var(--fs-sm); }
```

- [ ] **Step 4: Run to see it pass**

Run: `PYTHONPATH=src pixi run python -m pytest tests/integration/test_paste_preview.py tests/integration/test_smoke_bootstrap.py -q`
Expected: all pass.

Run: `pixi run smoke-browser`
Expected: all pass, including the 3 new tests.

- [ ] **Step 5: Full suite, then commit**

Run: `pixi run test` — expected: all pass.

```bash
git add src/seqsetup/routes/samples.py src/seqsetup/templates/runs/_paste_form.html src/seqsetup/templates/runs/_paste_preview.html src/seqsetup/templates/runs/_sample_section.html src/seqsetup/static/css/components.css src/seqsetup/static/js/app.js tests/integration/test_paste_preview.py tests/integration/test_smoke_bootstrap.py tests/browser/test_paste_preview.py
git commit -m "feat(paste): preview before adding samples, with test and lane pickers"
```
