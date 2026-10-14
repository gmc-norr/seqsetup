"""The index safety net's own model of the truth.

Shared by ``tests/integration/test_index_safety_net.py`` and
``tests/browser/test_index_safety_net.py``: the expected map, the i5
direction table, the reverse complement, and a Sample Sheet reader.

Nothing here calls application code. The expected map holds only what a test
itself sent plus the sequences the tests' own kits are built from; the sheets
are read with Python's ``csv`` module, never the application's parser; the
reverse complement and the i5 direction are written out here. An oracle that
asks the application what the answer is proves nothing.
"""

import csv
import io
from collections import Counter

# --------------------------------------------------------------------------
# Index sequences the net assigns
# --------------------------------------------------------------------------

_BASES = "ACGT"
_COMPLEMENT = {"A": "T", "C": "G", "G": "C", "T": "A", "N": "N"}

#: Length of every index the net assigns; the runs it builds read this many
#: index cycles, so no index is masked and no OverrideCycles hides a swap.
INDEX_LENGTH = 10

#: The least Hamming distance between any two sequences ``code_word`` makes.
#: A collision needs two samples in one lane whose i7s AND i5s are both
#: within 2 x barcode_mismatches (1 by default) of each other, so three
#: keeps every pair of the net's own indexes collision-free.
MIN_INDEX_DISTANCE = 3

#: How many sequences ``code_word`` can make (4 ** 5 free base-4 digits).
CODE_WORDS = 1024

#: The base that gives no signal on a 2-color instrument. An index whose first
#: two read bases are both dark is a Check error ("starts with two dark
#: bases"), so the net never hands one out: not at the start of a sequence
#: (an i7, or an i5 an instrument reads forward) and not at the start of its
#: reverse complement, which is the i5 an instrument reads reversed.
DARK_BASE = "G"


def code_word(n: int) -> str:
    """The ``n``-th sequence of a length-10 code whose words are at least
    ``MIN_INDEX_DISTANCE`` bases apart (0 <= n < ``CODE_WORDS``).

    The first five bases spell ``n`` in base 4; the last five are the sums of
    neighbouring pairs, mod 4. Each of the five free digits appears in two of
    those sums, and the sums' pairs form a ring, so changing one digit moves
    three positions; changing two moves at least four. The net asserts the
    distance it needs rather than trusting this note
    (``test_the_nets_own_sequences_are_far_apart``).
    """
    if not 0 <= n < CODE_WORDS:
        raise ValueError(f"code_word takes 0..{CODE_WORDS - 1}, not {n}")
    digits = [(n // 4 ** k) % 4 for k in range(5)]
    a, b, c, d, e = digits
    digits += [(a + b) % 4, (b + c) % 4, (c + d) % 4, (d + e) % 4, (e + a) % 4]
    return "".join(_BASES[k] for k in digits)


def _two_dark_bases_first(sequence: str) -> bool:
    return sequence[:2] == DARK_BASE * 2


def usable(sequence: str) -> bool:
    """A sequence the net may hand out: no instrument reads it starting with
    two dark bases, whichever direction it reads the i5 in."""
    return not _two_dark_bases_first(sequence) and \
        not _two_dark_bases_first(reverse_complement(sequence))


def hamming(left: str, right: str) -> int:
    """How many positions two equal-length sequences differ in."""
    assert len(left) == len(right), (left, right)
    return sum(1 for x, y in zip(left, right) if x != y)


def reverse_complement(sequence: str) -> str:
    """The net's own reverse complement — never the exporter's."""
    return "".join(_COMPLEMENT[base] for base in reversed(sequence))


#: Every sequence the net may hand out, in code order.
POOL = [word for word in (code_word(n) for n in range(CODE_WORDS)) if usable(word)]
_HALF = len(POOL) // 2


class Sequences:
    """Hands out i7 and i5 sequences from two disjoint halves of the pool, so
    an i7 written into an Index2 column (or the reverse) can never look
    right."""

    def __init__(self):
        self._i7 = 0
        self._i5 = _HALF

    def i7(self, count: int = 1) -> list[str]:
        words = POOL[self._i7:self._i7 + count]
        self._i7 += count
        assert self._i7 <= _HALF, "ran out of i7 sequences"
        return words

    def i5(self, count: int = 1) -> list[str]:
        words = POOL[self._i5:self._i5 + count]
        self._i5 += count
        assert self._i5 <= len(POOL), "ran out of i5 sequences"
        return words

    def pairs(self, count: int) -> list[tuple[str, str]]:
        return list(zip(self.i7(count), self.i5(count), strict=True))


# --------------------------------------------------------------------------
# How a sheet writes Index2
# --------------------------------------------------------------------------

AS_ENTERED = "as entered"
REVERSE_COMPLEMENT = "reverse complement"

# What the Index2 column of a Sample Sheet holds, per instrument and i5
# workflow, for an i5 entered in SeqSetup. Filled from Illumina's documented
# behaviour; cross-checked against the pinned exporter tests named beside
# each entry. If this table and the application disagree, that is a finding
# about one of them, never a reason to edit this table.
#
#   NovaSeq X Series, standard (the only workflow it has)
#       The i5 is read as its reverse complement, and the run's RunInfo.xml
#       marks index read 2 as reversed, so BCL Convert reverses the column
#       itself: Sample Sheet v2 carries the i5 as entered (and the sheet says
#       so with "IndexOrientation,Forward"). The NovaSeq X Series writes no
#       v1 (IEM) sheet at all.
#       Illumina, "Sample Sheet v2 Settings"/NovaSeq X Series index
#       orientation guidance.
#       Pinned by tests/unit/test_samplesheet_v2_exporter.py
#       ::test_export_novaseq_x_i5_forward and
#       tests/integration/test_sheet_targets.py CASES row 1.
#   NovaSeq 6000, v1.5 reagents
#       The i5 is read as its reverse complement and RunInfo.xml does not
#       mark it, so both sheets must carry the reverse complement.
#       Illumina, "Indexed Sequencing Overview"/NovaSeq 6000 v1.5 reagent
#       index orientation.
#       Pinned by tests/unit/test_samplesheet_v2_exporter.py
#       ::test_export_novaseq_6000_i5_reverse_complement,
#       tests/unit/test_samplesheet_v1_exporter.py
#       ::test_data_novaseq6000_reverse_complement_i5, and
#       tests/integration/test_sheet_targets.py CASES row 2.
#   NovaSeq 6000, v1.0 reagents
#       The i5 is read forward, so both sheets carry it as entered.
#       Same Illumina source; pinned by tests/integration/test_sheet_targets.py
#       CASES row 3 and tests/integration/test_run_checks_1b.py, which reads
#       the i5 the sheet wrote for each workflow.
I5_SHEET_DIRECTION = {
    ("NovaSeq X Series", ""): {"v2": AS_ENTERED, "v1": None},
    ("NovaSeq X Series", "Standard"): {"v2": AS_ENTERED, "v1": None},
    ("NovaSeq 6000", "v1.5 reagents"): {"v2": REVERSE_COMPLEMENT,
                                        "v1": REVERSE_COMPLEMENT},
    ("NovaSeq 6000", "v1.0 reagents"): {"v2": AS_ENTERED, "v1": AS_ENTERED},
}


def sheet_i5(i5: str, direction: str) -> str:
    """The i5 as a sheet column must hold it."""
    if not i5:
        return ""
    if direction == AS_ENTERED:
        return i5
    if direction == REVERSE_COMPLEMENT:
        return reverse_complement(i5)
    raise ValueError(f"unknown i5 direction {direction!r}")


# --------------------------------------------------------------------------
# Reading a Sample Sheet
# --------------------------------------------------------------------------

# How a sheet column is named in each sheet version: v2 writes Index/Index2,
# v1 writes index/index2. Matched case-insensitively on the header text.
_COLUMN_ROLES = {
    "sample_id": "sample_id",
    "lane": "lane",
    "index": "i7",
    "index2": "i5",
    "libraryname": "library_name",
}


class Section:
    """One ``[Name]`` section of a Sample Sheet, read with ``csv`` only."""

    def __init__(self, name: str, lines: list[str]):
        self.name = name
        self.lines = lines
        rows = list(csv.reader(io.StringIO("\n".join(lines))))
        self.header = rows[0] if rows else []
        self.rows = [row for row in rows[1:] if any(cell for cell in row)]
        self.roles = {}
        for position, cell in enumerate(self.header):
            role = _COLUMN_ROLES.get(cell.strip().lower())
            if role and role not in self.roles:
                self.roles[role] = position

    @property
    def names_samples(self) -> bool:
        return "sample_id" in self.roles

    def cell(self, row: list[str], role: str) -> str:
        position = self.roles.get(role)
        if position is None or position >= len(row):
            return ""
        return row[position]


def parse_sections(sheet: str) -> list[Section]:
    """Every ``[Name]`` section of a Sample Sheet, in sheet order."""
    sections, name, lines = [], None, []
    for raw in sheet.splitlines():
        line = raw.rstrip("\r")
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if name is not None:
                sections.append(Section(name, lines))
            name, lines = stripped, []
        elif stripped and name is not None:
            lines.append(line)
    if name is not None:
        sections.append(Section(name, lines))
    return sections


def data_sections(sheet: str) -> list[Section]:
    """The sections that name samples: every ``[..._Data]`` (v2) or ``[Data]``
    (v1) whose header has a Sample_ID column."""
    return [
        section for section in parse_sections(sheet)
        if (section.name.endswith("_Data]") or section.name == "[Data]")
        and section.names_samples
    ]


# --------------------------------------------------------------------------
# The expected map
# --------------------------------------------------------------------------

class Mismatch(AssertionError):
    """A sheet row does not hold what the test gave the sample."""


class Expected:
    """What the test sent: ``sample_id -> {"i7", "i5", "lanes"}``, plus a tally
    of which assign path put it there.

    Every value here comes from the test's own request or from the sequences
    its own kits are built from. Nothing is read back from the application.
    """

    def __init__(self, label: str = ""):
        self.label = label
        self.samples: dict[str, dict] = {}
        self.paths: Counter = Counter()

    # -- building -------------------------------------------------------

    def add(self, sample_id: str, lanes, path: str, i7: str = "", i5: str = ""):
        assert sample_id not in self.samples, f"{sample_id} added twice"
        self.samples[sample_id] = {"i7": i7, "i5": i5, "lanes": list(lanes)}
        self.paths[path] += 1

    def set_indexes(self, sample_id: str, path: str, i7=None, i5=None):
        """What one assign path gave a sample. ``None`` leaves a half alone."""
        row = self.samples[sample_id]
        if i7 is not None:
            row["i7"] = i7
        if i5 is not None:
            row["i5"] = i5
        self.paths[path] += 1

    def set_pair(self, sample_id: str, path: str, i7: str, i5: str):
        self.set_indexes(sample_id, path, i7=i7, i5=i5)

    def clear_indexes(self, sample_id: str, path: str):
        self.set_indexes(sample_id, path, i7="", i5="")

    def set_lanes(self, sample_id: str, lanes, path: str):
        self.samples[sample_id]["lanes"] = list(lanes)
        self.paths[path] += 1

    def rename(self, old: str, new: str, path: str):
        assert new not in self.samples, f"{new} is already a sample"
        self.samples[new] = self.samples.pop(old)
        self.paths[path] += 1

    def remove(self, sample_id: str, path: str):
        del self.samples[sample_id]
        self.paths[path] += 1

    def note(self, path: str):
        """An edit that must change no index and no lane."""
        self.paths[path] += 1

    def copy(self, label: str) -> "Expected":
        twin = Expected(label)
        twin.samples = {name: dict(row, lanes=list(row["lanes"]))
                        for name, row in self.samples.items()}
        twin.paths = Counter(self.paths)
        return twin

    # -- what the map itself must hold ----------------------------------

    def rows_with_a_lane(self) -> Counter:
        """One expected row per (sample, lane): what a section with a Lane
        column must hold, no row missing, none extra, none twice."""
        return Counter((name, str(lane))
                       for name, row in self.samples.items()
                       for lane in (row["lanes"] or [""]))

    def rows_without_a_lane(self) -> Counter:
        return Counter(self.samples.keys())

    def assert_no_lane_shares_an_index(self):
        """The net's own check that the run it built can pass the real index
        collision check: no two samples in one lane whose i7s and i5s are
        both within two bases of each other."""
        by_lane: dict[str, list[tuple[str, dict]]] = {}
        for name, row in self.samples.items():
            for lane in (row["lanes"] or [""]):
                by_lane.setdefault(str(lane), []).append((name, row))
        for lane, members in sorted(by_lane.items()):
            for position, (name, row) in enumerate(members):
                for other_name, other in members[position + 1:]:
                    if not (row["i7"] and other["i7"]):
                        continue
                    if hamming(row["i7"], other["i7"]) > 2:
                        continue
                    if row["i5"] and other["i5"] and \
                            hamming(row["i5"], other["i5"]) > 2:
                        continue
                    raise Mismatch(
                        f"{self.label}: the net built a run the index check must "
                        f"refuse: {name} and {other_name} are both in lane {lane} "
                        f"with i7 {row['i7']}/{other['i7']} and i5 "
                        f"{row['i5']}/{other['i5']}"
                    )

    # -- comparing a sheet ----------------------------------------------

    def check_sheet(self, sheet: str, version: str, direction: str) -> int:
        """Compare every row of every sample-naming section of ``sheet`` to the
        map, then the rows as multisets. Returns the number of rows checked.

        ``version`` is "v2" or "v1" (for the message); ``direction`` says what
        the Index2 column must hold, from ``I5_SHEET_DIRECTION``.
        """
        sections = data_sections(sheet)
        if not sections:
            raise Mismatch(
                f"{self.label}: the stored {version} sheet has no section that "
                f"names samples. Sections: "
                f"{[s.name for s in parse_sections(sheet)]}"
            )
        checked = 0
        for section in sections:
            checked += self._check_section(section, version, direction)
        return checked

    def _check_section(self, section: Section, version: str, direction: str) -> int:
        has_lane = "lane" in section.roles
        found: Counter = Counter()
        for number, row in enumerate(section.rows, start=1):
            name = section.cell(row, "sample_id")
            where = (f"{self.label}: {version} sheet, section {section.name}, "
                     f"row {number} (Sample_ID {name!r})")
            if name not in self.samples:
                raise Mismatch(
                    f"{where}: this sheet names a sample the test never put in "
                    f"the run. The run holds: {sorted(self.samples)[:8]}..."
                )
            want = self.samples[name]
            lane = section.cell(row, "lane")
            if has_lane:
                wanted_lanes = [str(one) for one in want["lanes"]] or [""]
                if lane not in wanted_lanes:
                    raise Mismatch(
                        f"{where}: Lane is {lane!r}; the test put this sample in "
                        f"lane(s) {wanted_lanes}"
                    )
            if "i7" in section.roles:
                self._same(section.cell(row, "i7"), want["i7"], "Index", where)
            if "i5" in section.roles:
                self._same(section.cell(row, "i5"),
                           sheet_i5(want["i5"], direction),
                           f"Index2 ({direction} of {want['i5'] or 'no i5'})", where)
            if "library_name" in section.roles:
                # [Cloud_Data]: the sheet's own second witness. The library
                # name holds both sequences as entered, whatever the
                # instrument reads.
                wanted = (f"{name}_{want['i7']}_{want['i5']}"
                          if want["i7"] and want["i5"] else name)
                self._same(section.cell(row, "library_name"), wanted,
                           "LibraryName", where)
            found[(name, lane) if has_lane else name] += 1
        want_rows = self.rows_with_a_lane() if has_lane else self.rows_without_a_lane()
        if found != want_rows:
            missing = want_rows - found
            extra = found - want_rows
            raise Mismatch(
                f"{self.label}: {version} sheet, section {section.name}: the rows "
                f"are not one per {'(sample, lane)' if has_lane else 'sample'}. "
                f"Missing: {sorted(missing.elements())[:8]}. "
                f"Extra or twice: {sorted(extra.elements())[:8]}."
            )
        return len(section.rows)

    def check_json(self, payload: dict, direction: str) -> int:
        """The JSON export's sample list: a third witness of the same map."""
        samples = payload.get("samples")
        if not isinstance(samples, list) or not samples:
            raise Mismatch(f"{self.label}: the stored JSON lists no samples")
        seen = Counter()
        for entry in samples:
            name = entry.get("sample_id")
            where = f"{self.label}: JSON export, sample {name!r}"
            if name not in self.samples:
                raise Mismatch(f"{where}: the JSON names a sample the test never "
                               f"put in the run")
            want = self.samples[name]
            self._same((entry.get("index1") or {}).get("sequence") or "",
                       want["i7"], "index1.sequence", where)
            self._same((entry.get("index2") or {}).get("sequence") or "",
                       want["i5"], "index2.sequence", where)
            self._same(entry.get("samplesheet_index2") or "",
                       sheet_i5(want["i5"], direction), "samplesheet_index2", where)
            if [str(one) for one in (entry.get("lanes") or [])] != \
                    [str(one) for one in want["lanes"]]:
                raise Mismatch(
                    f"{where}: lanes are {entry.get('lanes')}; the test put this "
                    f"sample in {want['lanes']}"
                )
            seen[name] += 1
        if seen != self.rows_without_a_lane():
            raise Mismatch(
                f"{self.label}: the JSON export's samples are not one per sample. "
                f"Missing: {sorted((self.rows_without_a_lane() - seen).elements())}. "
                f"Extra or twice: {sorted((seen - self.rows_without_a_lane()).elements())}."
            )
        return len(samples)

    def check_page(self, shown: dict) -> int:
        """What the run page shows for each sample, read the way ``app.js``
        reads it: ``sample_id -> {"i7", "i5", "lanes"}`` from each row's
        ``data-i7``/``data-i5`` and its lanes cell."""
        if set(shown) != set(self.samples):
            raise Mismatch(
                f"{self.label}: the page shows samples "
                f"{sorted(set(shown) ^ set(self.samples))} the map does not, or "
                f"the other way round"
            )
        for name, row in shown.items():
            want = self.samples[name]
            where = f"{self.label}: the run page's row for {name!r}"
            self._same(row["i7"], want["i7"], "data-i7", where)
            self._same(row["i5"], want["i5"], "data-i5", where)
            if sorted(row["lanes"]) != sorted(str(one) for one in want["lanes"]):
                raise Mismatch(
                    f"{where}: shows lanes {row['lanes']}; the test put this "
                    f"sample in {want['lanes']}"
                )
        return len(shown)

    @staticmethod
    def _same(found: str, wanted: str, column: str, where: str):
        if found != wanted:
            raise Mismatch(f"{where}: {column} is {found!r}, expected {wanted!r}")
