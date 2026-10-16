"""The index safety net: no sample ever carries another sample's index, or
the wrong lane, in a stored Sample Sheet.

The user's question after the index mix-up audit (2026-10-14): "no sample may
get the wrong indexes in the sample sheet; can we be 110% sure?". This test
drives the real routes, the way the pages do: it builds a run of 40 to 96
samples by every path the app has for setting a sample's index or its lanes,
marks the run Ready through its route, reads the stored sheets back through
the Bearer API, and compares every row to a map it keeps itself
(``tests/index_safety_net.py``).

The map is the test's own. It holds only what the test sent, plus the
sequences the kits defined here are built from. Nothing is read back from the
repository, and no exporter, parser or ``reverse_complement`` from ``src/``
is called to work out what a row should hold: an oracle that asks the
application for the answer proves nothing. What the *page* shows is fair
game, and is read the way ``app.js`` reads it -- a chip's
``data-kit-fingerprint``, the panel's order, each row's ``data-i7`` --
because that is the input the app gets from a browser.

A new way to set a sample's index or lane must be added to ``_ASSIGN_PATHS``
or ``_LANE_PATHS`` below, or the net will not cover it. Templates are not in
them: a template saved through the app holds no samples
(``tests/integration/test_run_templates_routes.py``), and one stored with
samples before copies them through the same ``build_draft_run`` that "a copy
of the run" drives.

Seeds: a few fixed ones by default. ``SEQSETUP_SAFETY_NET_SEEDS=1-200`` (or a
comma-separated list) runs a soak instead; see
``docs/development/contributing.rst``.
"""

import html
import json
import os
import random
import re

import pytest

from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)
from seqsetup.services import sample_api as sample_api_module

from tests.index_safety_net import (AS_ENTERED, I5_SHEET_DIRECTION, INDEX_LENGTH,
                                    MIN_INDEX_DISTANCE, POOL, REVERSE_COMPLEMENT,
                                    Expected, Sequences, data_sections, hamming,
                                    reverse_complement, usable)

from .conftest import hold_edit_lock, mark_ready, nothing_stored
from .test_served_runs import _token

ORIGIN = {"Origin": "http://testserver"}

TEST_ID = "NET"
TEST_VERSION = "1.0.0"
BCL_SOFTWARE = "4.3.6"  # what config/instruments.yaml says both instruments run

# The runs the net builds: (id, instrument, flow cell, i5 workflow, lanes).
# One instrument writes Index2 as entered, one writes its reverse complement,
# so a flipped i5 rule cannot pass (``I5_SHEET_DIRECTION``).
CASES = [
    ("novaseq-x", InstrumentPlatform.NOVASEQ_X, "10B", "", 8),
    ("novaseq-6000-v15", InstrumentPlatform.NOVASEQ_6000, "S4", "v1.5 reagents", 4),
    ("novaseq-6000-v10", InstrumentPlatform.NOVASEQ_6000, "S4", "v1.0 reagents", 4),
]

# Every path that sets a sample's index, and every path that sets its lanes.
# The net asserts each one was used (``_assert_every_path_was_used``).
_ASSIGN_PATHS = [
    "paste index columns",
    "a paste from a file",
    "LIMS index fields",
    "one drop: a pair",
    "one drop: an i7",
    "one drop: an i5",
    "a single index onto a pair",
    "drop on ticked rows",
    "one i7 on ticked rows",
    "one i5 on ticked rows",
    "several indexes dropped at once",
    "several indexes dropped onto assigned rows",
    "a drop from one of two kit versions",
    "clear, then drop again",
    "clear one half, then drop again",
    "drop onto an assigned sample",
    "fill in order",
    "a drop after Ready, then Ready again",
]
_LANE_PATHS = [
    "the paste's lanes",
    "the LIMS import's picked lanes",
    "a sample added by hand",
    "set lanes on a subset",
]
# Edits that must move no index and no lane.
_QUIET_PATHS = [
    "rename a sample",
    "delete samples",
    "delete one sample by hand",
    "set the test",
    "set the barcode mismatches",
    "set the override cycles",
]
_COPY_PATH = "a copy of the run"

ALL_PATHS = _ASSIGN_PATHS + _LANE_PATHS + _QUIET_PATHS + [_COPY_PATH]

# Which pairs of the unique-dual kit each path hands out. Two paths must never
# share one: one index on two samples in one lane is a collision the real
# checks refuse, and the net's own guard says so before Mark Ready does
# (``Expected.assert_no_lane_shares_an_index``). The ticked-rows drop is the
# one path that gives its index to several samples, and it puts each of them
# in a lane of its own.
_SEED_PAIRS = slice(0, 4)        # one single drop each, to start the run off
_TICKED_PAIR = 4                 # one index on every ticked row
_CLEARED_PAIR = 5                # dropped again after a clear
_REPLACING_PAIR = 6              # dropped onto a sample that already has one
_REPROMOTED_PAIR = 7             # dropped after Ready, before Ready again
_BULK_PAIRS = slice(8, 16)       # several dropped at once
_BULK_AGAIN_PAIRS = slice(16, 24)  # several dropped onto rows that have one

# And which of the combinatorial kit's single indexes. Same rule: one
# position per path, so no two samples share an index by accident.
_COMB_ON_EMPTY = 0     # an i7 and an i5 onto a row with no index
_COMB_ON_A_PAIR = 1    # one single index onto a sample that has a pair
_COMB_ON_TICKED = 2    # one i7, then one i5, on two ticked rows
_COMB_HALF_CLEAR = 3   # the i5 dropped again after half a clear


def _seeds() -> list[int]:
    """The default seeds, or the soak's (``SEQSETUP_SAFETY_NET_SEEDS``)."""
    asked = os.environ.get("SEQSETUP_SAFETY_NET_SEEDS", "").strip()
    if not asked:
        # One seed per case, so every instrument and i5 workflow in CASES
        # reaches a stored sheet (test_the_default_seeds_reach_every_case).
        return [12, 404, 9001]
    seeds: list[int] = []
    for part in asked.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part.lstrip("-"):
            low, high = part.split("-", 1)
            seeds.extend(range(int(low), int(high) + 1))
        else:
            seeds.append(int(part))
    assert seeds, f"SEQSETUP_SAFETY_NET_SEEDS={asked!r} names no seed"
    return seeds


# --------------------------------------------------------------------------
# Reading the pages, the way app.js reads them
# --------------------------------------------------------------------------

_ROW = re.compile(
    r'<tr id="sample-row-(?P<row_id>[^"]+)"[^>]*'
    r'data-i7="(?P<i7>[^"]*)" data-i5="(?P<i5>[^"]*)">(?P<body>.*?)</tr>',
    re.S,
)
_SHOWN_ID = re.compile(r'<td class="sample-id-cell" title="[^"]*">([^<]*)</td>')
_SHOWN_LANES = re.compile(r'<span class="lanes-display">([^<]*)</span>')
_CHIP = re.compile(r'<div class="draggable-index-compact(?P<attrs>.*?)>', re.S)


def _attr(attrs: str, name: str) -> str:
    found = re.search(rf'{name}="([^"]*)"', attrs)
    return found.group(1) if found else ""


def page_rows(client, run_id: str) -> list[dict]:
    """Each sample row of the run page, in the order the page shows them:
    the row's own id, the sample ID it shows, the sequences its ``data-i7``
    and ``data-i5`` carry (what a drop sends back), and its lanes."""
    page = client.get(f"/runs/{run_id}")
    assert page.status_code == 200, page.text[:300]
    rows = []
    for found in _ROW.finditer(page.text):
        body = found.group("body")
        shown_id = _SHOWN_ID.search(body)
        lanes = _SHOWN_LANES.search(body)
        assert shown_id, (
            f"the run page's row {found.group('row_id')} shows no sample ID "
            f"cell; the row template's shape changed")
        rows.append({
            "row_id": found.group("row_id"),
            "sample_id": shown_id.group(1),
            "i7": found.group("i7"),
            "i5": found.group("i5"),
            "lanes": [] if not lanes or lanes.group(1) == "All"
                     else lanes.group(1).split(","),
        })
    return rows


def page_panel(client, kit_id: str) -> list[dict]:
    """The index panel's chips in the order it shows them -- the panel order a
    multi-index drop must fill rows in -- each with the kit id and fingerprint
    the chip carries and the sequences its tooltip shows."""
    fragment = client.get("/indexes/kit-content", params={"selected_kit": kit_id})
    assert fragment.status_code == 200, fragment.text[:300]
    chips = []
    for found in _CHIP.finditer(fragment.text):
        attrs = found.group("attrs")
        # A pair chip's tooltip reads "<name>&#10;i7: <i7>&#10;i5: <i5>..."; a
        # single one's "<name>&#10;Well: ...&#10;Sequence: <seq>"
        # (templates/wizard/_draggable_index_pair.html, _draggable_index.html).
        title = _attr(attrs, "title")
        chips.append({
            "id": _attr(attrs, "data-index-pair-id") or _attr(attrs, "data-index-id"),
            "type": _attr(attrs, "data-index-type"),
            "name": _attr(attrs, "data-index-name"),
            "kit_id": _attr(attrs, "data-kit-id"),
            "kit_fingerprint": _attr(attrs, "data-kit-fingerprint"),
            "i7": _shown_sequence(title, "i7: "),
            "i5": _shown_sequence(title, "i5: "),
            "sequence": _shown_sequence(title, "Sequence: "),
        })
    assert chips, f"the index panel shows no chip for {kit_id}"
    return chips


def _shown_sequence(title: str, label: str) -> str:
    found = re.search(re.escape(label) + r"([ACGTN]+)", title)
    return found.group(1) if found else ""


# --------------------------------------------------------------------------
# The kits the net defines, from its own sequences
# --------------------------------------------------------------------------

class Kits:
    """Every kit the net assigns from, and the sequences each index holds.

    Built from ``Sequences``, so the i7s and the i5s come from two disjoint
    halves of the code: an i7 written into an Index2 column can never look
    right.
    """

    def __init__(self, ctx, how_many_to_fill: int):
        self.sequences = Sequences()
        self.dual = self._pair_kit("Net-Dual", "1.0", 24)
        self.fill = self._pair_kit("Net-Fill", "1.0", how_many_to_fill + 4)
        self.comb = self._combinatorial("Net-Comb", "1.0", 12)
        # Two versions of one kit: the same index names, other sequences. A
        # drop names the version by kit_id and fingerprint, and the sample
        # must get that version's sequences (index mix-up audit #6).
        self.twice_old = self._pair_kit("Net-Twice", "1.0", 4)
        self.twice_new = self._pair_kit("Net-Twice", "2.0", 4,
                                        names=[p.name for p in self.twice_old.index_pairs])
        self.all = [self.dual, self.fill, self.comb, self.twice_old, self.twice_new]
        for kit in self.all:
            ctx.index_kit_repo.save(kit)

    def _pair_kit(self, name, version, count, names=None):
        pairs = self.sequences.pairs(count)
        labels = names or [f"{name}-P{k:02d}" for k in range(count)]
        return IndexKit(
            name=name, version=version, index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[
                IndexPair(
                    id=f"{name}_{labels[k]}", name=labels[k],
                    index1=Index(name=labels[k], sequence=i7, index_type=IndexType.I7),
                    index2=Index(name=labels[k], sequence=i5, index_type=IndexType.I5),
                )
                for k, (i7, i5) in enumerate(pairs)
            ],
        )

    def _combinatorial(self, name, version, count):
        return IndexKit(
            name=name, version=version, index_mode=IndexMode.COMBINATORIAL,
            i7_indexes=[Index(name=f"{name}-N{k:02d}", sequence=sequence,
                              index_type=IndexType.I7)
                        for k, sequence in enumerate(self.sequences.i7(count))],
            i5_indexes=[Index(name=f"{name}-S{k:02d}", sequence=sequence,
                              index_type=IndexType.I5)
                        for k, sequence in enumerate(self.sequences.i5(count))],
        )

    def every_sequence(self) -> list[str]:
        found = []
        for kit in self.all:
            for pair in kit.index_pairs:
                found += [pair.index1_sequence, pair.index2_sequence]
            found += [index.sequence for index in kit.i7_indexes + kit.i5_indexes]
        return [sequence for sequence in found if sequence]


def _seed_profiles(ctx):
    """One BCLConvert profile with a Lane column, as the shipped profile has,
    and a test that lists it, so Mark Ready writes the profile-driven
    sections a sequencer really reads."""
    # Imported here: a module-level ``TestProfile`` makes pytest warn that it
    # cannot collect a class whose name starts with Test.
    from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
    ctx.app_profile_repo.save(ApplicationProfile(
        name="NetBCL", version=TEST_VERSION, application_type="Dragen",
        application_name="BCLConvert", settings={"SoftwareVersion": BCL_SOFTWARE},
        data={"BarcodeMismatchesIndex1": 1, "BarcodeMismatchesIndex2": 1},
        data_fields=["Sample_ID", "Lane", "Index", "Index2", "OverrideCycles",
                     "BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"],
    ))
    ctx.test_profile_repo.save(TestProfile(
        test_type=TEST_ID, test_name="Index safety net test", description="net",
        version=TEST_VERSION,
        application_profiles=[ApplicationProfileReference(
            profile_name="NetBCL", profile_version=TEST_VERSION)],
    ))


# --------------------------------------------------------------------------
# The net
# --------------------------------------------------------------------------

class Net:
    """Drives one run through every path, keeping the expected map as it goes."""

    def __init__(self, client, ctx, monkeypatch, seed: int, case, how_many: int):
        self.client = client
        self.ctx = ctx
        self.seed = seed
        self.rng = random.Random(seed)
        self.case_id, self.instrument, self.flowcell, self.workflow, self.lanes = case
        self.how_many = how_many
        self.direction = I5_SHEET_DIRECTION[(self.instrument.value, self.workflow)]
        self.run_id = f"safety-net-{self.case_id}-{seed}"
        self.expected = Expected(f"seed {seed} ({self.case_id})")
        self.names = iter(f"NET-{n:04d}" for n in range(1, 400))
        # Samples the ticked-rows drop shares one index with: their lanes are
        # pairwise disjoint and nothing moves them afterwards.
        self.one_index_group: set[str] = set()

        _seed_profiles(ctx)
        self.kits = Kits(ctx, how_many)
        self.lims_rows: dict[str, list[dict]] = {}
        self._start_lims(monkeypatch)

        run = SequencingRun(
            id=self.run_id, run_name=f"Index safety net {seed}",
            instrument_platform=self.instrument, flowcell_type=self.flowcell,
            i5_workflow=self.workflow,
            run_cycles=RunCycles(151, 151, INDEX_LENGTH, INDEX_LENGTH),
        )
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, self.run_id)

    # -- the LIMS the import reads -------------------------------------

    def _start_lims(self, monkeypatch):
        self.ctx.sample_api_config_repo.save(SampleApiConfig(
            base_url="https://lims.example.org/api", enabled=True))
        rows = self.lims_rows

        def answer(url, api_key=""):
            if "/worksheets/" in url:
                return [dict(row) for row in rows.get(url.rsplit("/", 1)[-1], [])]
            return [{"id": worksheet} for worksheet in sorted(rows)]

        monkeypatch.setattr(sample_api_module, "_api_get", answer)

    # -- small helpers -------------------------------------------------

    def _post(self, path: str, **data):
        return self.client.post(f"/runs/{self.run_id}{path}", data=data, headers=ORIGIN)

    def _shown(self, row_ids: list[str]) -> str:
        """The index the page shows in each of those rows, as app.js sends it
        with every single-row assign and clear: the route refuses a row whose
        index has moved since the page was drawn (F8)."""
        by_id = {row["row_id"]: row for row in self.rows()}
        return json.dumps([[by_id[rid]["i7"] if rid in by_id else "",
                            by_id[rid]["i5"] if rid in by_id else ""]
                           for rid in row_ids])

    def _some_lanes(self, how_many: int) -> list[int]:
        return sorted(self.rng.sample(range(1, self.lanes + 1), how_many))

    def _lanes_above_one(self, how_many: int) -> list[int]:
        """Lanes that do not include lane 1: a path that quietly fell back to
        lane 1 would otherwise be invisible whenever lane 1 was picked."""
        return sorted(self.rng.sample(range(2, self.lanes + 1), how_many))

    def rows(self) -> list[dict]:
        return page_rows(self.client, self.run_id)

    def unindexed(self) -> list[dict]:
        return [row for row in self.rows() if not row["i7"] and not row["i5"]]

    def indexed(self) -> list[dict]:
        return [row for row in self.rows() if row["i7"]]

    def longest_unindexed_stretch(self) -> list[dict]:
        """The longest run of rows with no index, in table order: what a
        several-index drop can fill in one go."""
        best: list[dict] = []
        current: list[dict] = []
        for row in self.rows():
            if row["i7"] or row["i5"]:
                current = []
                continue
            current.append(row)
            if len(current) > len(best):
                best = list(current)
        return best

    def chip_for(self, kit, index_id: str, kind: str = "pair") -> dict:
        """The panel's chip for one index, and a check that the chip shows the
        sequences this test's own kit was built from."""
        chips = page_panel(self.client, kit.kit_id)
        chip = next(one for one in chips if one["id"] == index_id and one["type"] == kind)
        if kind == "pair":
            pair = next(p for p in kit.index_pairs if p.id == index_id)
            shown, wanted = ((chip["i7"], chip["i5"]),
                             (pair.index1_sequence, pair.index2_sequence))
        else:
            holds = kit.i7_indexes if kind == "i7" else kit.i5_indexes
            index = next(i for i in holds
                         if f"{kit.name}_{kind}_{i.name}" == index_id)
            shown, wanted = (chip["sequence"],), (index.sequence,)
        assert shown == wanted, (
            f"{self.expected.label}: the panel's chip for {index_id} shows "
            f"{shown}, but this test built it from {wanted}"
        )
        return chip

    def _drop(self, row_id: str, chip: dict):
        """One index dropped on one row, as ``app.js`` sends it."""
        values = {"kit_id": chip["kit_id"], "kit_fingerprint": chip["kit_fingerprint"]}
        if chip["type"] == "pair":
            values["index_pair_id"] = chip["id"]
        else:
            values["index_id"] = chip["id"]
            values["index_type"] = chip["type"]
        values["target_indexes"] = self._shown([row_id])
        answer = self._post(f"/samples/{row_id}/assign-index", **values)
        assert answer.status_code == 200, answer.text[:300]

    # -- the paths that make samples -----------------------------------

    def paste_with_indexes(self, how_many: int):
        """A paste whose header names the index columns; Preview, then Add.
        A paste never carries a lane column -- the lanes come from the Lanes
        picker (``services/sample_parser.py``), and the net proves that in
        ``test_a_paste_may_not_carry_a_lane_column``."""
        lanes = self._lanes_above_one(self.rng.choice([1, 2]))
        sequences = self.kits.sequences
        made = []
        lines = ["sample_id\tindex_i7\tindex_i5"]
        for i7, i5 in sequences.pairs(how_many):
            name = next(self.names)
            lines.append(f"{name}\t{i7}\t{i5}")
            made.append((name, i7, i5))
        paste = "\n".join(lines) + "\n"

        preview = self._post("/samples/preview", paste_data=paste,
                             lanes=[str(lane) for lane in lanes])
        assert preview.status_code == 200, preview.text[:300]
        for name, i7, i5 in made:
            assert name in preview.text and i7 in preview.text and i5 in preview.text, (
                f"the paste's preview does not show {name}"
            )
        added = self.client.post(
            f"/runs/{self.run_id}/samples/bulk",
            data={"paste_data": paste, "lanes": [str(lane) for lane in lanes]},
            headers=ORIGIN)
        assert added.status_code == 200, added.text[:300]
        assert "rejected" not in added.text, added.text[:400]

        for name, i7, i5 in made:
            self.expected.add(name, lanes, "paste index columns", i7=i7, i5=i5)
        self.expected.paths["the paste's lanes"] += 1

    def paste_from_a_file(self, how_many: int):
        """The same paste, sent as an uploaded file: the route reads the file
        with the same parser, and the net must see it too (review P2-6)."""
        lanes = self._lanes_above_one(1)
        made = []
        lines = ["sample_id,index_i7,index_i5"]
        for i7, i5 in self.kits.sequences.pairs(how_many):
            name = next(self.names)
            lines.append(f"{name},{i7},{i5}")
            made.append((name, i7, i5))
        added = self.client.post(
            f"/runs/{self.run_id}/samples/bulk",
            files={"sample_file": ("worklist.csv",
                                   ("\n".join(lines) + "\n").encode(), "text/csv")},
            data={"lanes": [str(lane) for lane in lanes]}, headers=ORIGIN)
        assert added.status_code == 200, added.text[:300]
        assert "rejected" not in added.text, added.text[:400]
        for name, i7, i5 in made:
            self.expected.add(name, lanes, "a paste from a file", i7=i7, i5=i5)
        self.expected.paths["the paste's lanes"] += 1

    def paste_without_indexes(self, how_many: int):
        """A paste of sample IDs only, on its own picked lanes."""
        lanes = self._some_lanes(1)
        made = [next(self.names) for _ in range(how_many)]
        paste = "sample_id\n" + "".join(f"{name}\n" for name in made)
        added = self.client.post(
            f"/runs/{self.run_id}/samples/bulk",
            data={"paste_data": paste, "lanes": [str(lane) for lane in lanes]},
            headers=ORIGIN)
        assert added.status_code == 200, added.text[:300]
        assert "rejected" not in added.text, added.text[:400]
        for name in made:
            self.expected.add(name, lanes, "paste no index columns")
        self.expected.paths["the paste's lanes"] += 1

    def lims_import(self, how_many: int, with_indexes: bool, worksheet: str):
        """A worklist import: Preview, then the preview's own Import button,
        on the lanes picked for the import."""
        lanes = (self._lanes_above_one if with_indexes else self._some_lanes)(
            self.rng.choice([1, 2]))
        made = []
        rows = []
        pairs = self.kits.sequences.pairs(how_many) if with_indexes \
            else [("", "")] * how_many
        for i7, i5 in pairs:
            name = next(self.names)
            row = {"sample_id": name}
            if with_indexes:
                row["index_i7"], row["index_i5"] = i7, i5
            rows.append(row)
            made.append((name, i7, i5))
        self.lims_rows[worksheet] = rows

        shown = self.client.get(
            f"/runs/{self.run_id}/samples/preview-worklist",
            params={"worklist_id": worksheet, "lanes": [str(lane) for lane in lanes]})
        assert shown.status_code == 200, shown.text[:300]
        plan = re.search(r'name="plan" value="([^"]*)"', shown.text)
        assert plan, f"the worklist preview offers no import: {shown.text[:400]}"
        picked = re.findall(r'<input type="hidden" name="lanes" value="(\d+)">', shown.text)
        assert picked == [str(lane) for lane in lanes], (
            f"the preview shows lanes {picked}, the import picked {lanes}")
        imported = self._post("/samples/fetch-worklist", worklist_id=worksheet,
                              plan=html.unescape(plan.group(1)), lanes=picked)
        assert imported.status_code == 200, imported.text[:300]

        path = "LIMS index fields" if with_indexes else "LIMS no index fields"
        for name, i7, i5 in made:
            self.expected.add(name, lanes, path, i7=i7, i5=i5)
        self.expected.paths["the LIMS import's picked lanes"] += 1

    def add_by_hand(self, how_many: int):
        """A sample added one at a time: the app gives it lane 1."""
        for _ in range(how_many):
            name = next(self.names)
            answer = self._post("/samples", sample_id=name)
            assert answer.status_code == 200, answer.text[:300]
            self.expected.add(name, [1], "a sample added by hand")

    # -- the paths that set an index -----------------------------------

    def drop_one_pair(self, rows: list[dict], kit=None, path="one drop: a pair"):
        kit = kit or self.kits.dual
        for offset, row in enumerate(rows):
            pair = kit.index_pairs[_SEED_PAIRS][offset]
            chip = self.chip_for(kit, pair.id)
            self._drop(row["row_id"], chip)
            self.expected.set_pair(row["sample_id"], path,
                                   i7=pair.index1_sequence, i5=pair.index2_sequence)

    def _drop_single(self, row: dict, kind: str, which: int, path: str):
        kit = self.kits.comb
        holds = kit.i7_indexes if kind == "i7" else kit.i5_indexes
        index = holds[which]
        self._drop(row["row_id"],
                   self.chip_for(kit, f"{kit.name}_{kind}_{index.name}", kind))
        self.expected.set_indexes(row["sample_id"], path,
                                  **{kind: index.sequence})
        return index

    def drop_an_i7_and_an_i5(self, row: dict):
        """A single i7 and a single i5 from a combinatorial kit, onto a row
        with no index."""
        self._drop_single(row, "i7", _COMB_ON_EMPTY, "one drop: an i7")
        self._drop_single(row, "i5", _COMB_ON_EMPTY, "one drop: an i5")

    def drop_a_single_index_onto_a_pair(self, row: dict):
        """One single index dropped on a sample that already holds a pair:
        the pair goes, i7 and i5 both, and the sample keeps only what was
        dropped (``replaceDropConfirmed`` in app.js). Then the other half is
        dropped, so the sample ends with a full pair of single indexes
        (review P1-1: nothing drove this, and the only thing that makes the
        drop take effect is ``Sample.assign_index1`` clearing index_pair)."""
        shown = next(one for one in self.rows() if one["row_id"] == row["row_id"])
        assert shown["i7"] and shown["i5"], "this path needs a sample with a pair"
        i7 = self._drop_single(row, "i7", _COMB_ON_A_PAIR, "a single index onto a pair")
        # The i5 of the pair went with it; the map says so.
        self.expected.set_indexes(row["sample_id"], "a single index onto a pair", i5="")
        gone = next(one for one in self.rows() if one["row_id"] == row["row_id"])
        assert (gone["i7"], gone["i5"]) == (i7.sequence, ""), (
            f"{self.expected.label}: a single i7 dropped on a paired sample left "
            f"{gone}; the pair must go, i7 and i5 both")
        self._drop_single(row, "i5", _COMB_ON_A_PAIR, "a single index onto a pair")

    def drop_on_ticked_rows(self, rows: list[dict]):
        """One index dropped while several rows are ticked: every ticked row
        gets it, so they must be in different lanes."""
        for offset, row in enumerate(rows):
            lane = [offset + 1]
            answer = self._post("/samples/set-lanes",
                                sample_ids=json.dumps([row["row_id"]]),
                                lanes=json.dumps(lane))
            assert answer.status_code == 200, answer.text[:300]
            self.expected.set_lanes(row["sample_id"], lane, "set lanes on a subset")
            self.one_index_group.add(row["sample_id"])

        pair = self.kits.dual.index_pairs[_TICKED_PAIR]
        chip = self.chip_for(self.kits.dual, pair.id)
        answer = self._post("/samples/assign-index-to-selected",
                            sample_ids=json.dumps([row["row_id"] for row in rows]),
                            target_indexes=self._shown([row["row_id"] for row in rows]),
                            index_pair_id=chip["id"], kit_id=chip["kit_id"],
                            kit_fingerprint=chip["kit_fingerprint"])
        assert answer.status_code == 200, answer.text[:300]
        for row in rows:
            self.expected.set_pair(row["sample_id"], "drop on ticked rows",
                                   i7=pair.index1_sequence, i5=pair.index2_sequence)

    def _a_stretch_to_fill(self) -> list[dict]:
        """Consecutive rows with no index, for a several-index drop: the server
        refuses a drop whose rows are not the ones the page named."""
        stretch = self.longest_unindexed_stretch()
        assert len(stretch) >= 3, (
            f"the net needs three rows with no index in a row, found {len(stretch)}")
        return stretch[:min(len(stretch), self.rng.randint(3, 6))]

    def _a_stretch_already_filled(self) -> list[dict]:
        """Consecutive rows that all carry an index: what a several-index drop
        replaces, which app.js asks about first (``multiDropWarning``) and the
        server refuses if any row's index changed since the page was loaded."""
        best: list[dict] = []
        current: list[dict] = []
        for row in self.rows():
            if not row["i7"] or row["sample_id"] in self.one_index_group:
                current = []
                continue
            current.append(row)
            if len(current) > len(best):
                best = list(current)
        assert len(best) >= 3, (
            f"the net needs three rows with an index in a row, found {len(best)}")
        return best[:min(len(best), self.rng.randint(3, 6))]

    def drop_one_single_index_on_ticked_rows(self, rows: list[dict]):
        """The single-index branch of assign-index-to-selected: one i7, then
        one i5, to the same ticked rows. They end up with the same pair of
        sequences, so each needs a lane of its own (review P2-6)."""
        for offset, row in enumerate(rows):
            lane = [offset + 1]
            answer = self._post("/samples/set-lanes",
                                sample_ids=json.dumps([row["row_id"]]),
                                lanes=json.dumps(lane))
            assert answer.status_code == 200, answer.text[:300]
            self.expected.set_lanes(row["sample_id"], lane, "set lanes on a subset")
            self.one_index_group.add(row["sample_id"])

        kit = self.kits.comb
        for kind, path in (("i7", "one i7 on ticked rows"),
                           ("i5", "one i5 on ticked rows")):
            holds = kit.i7_indexes if kind == "i7" else kit.i5_indexes
            index = holds[_COMB_ON_TICKED]
            chip = self.chip_for(kit, f"{kit.name}_{kind}_{index.name}", kind)
            answer = self._post(
                "/samples/assign-index-to-selected",
                sample_ids=json.dumps([row["row_id"] for row in rows]),
                target_indexes=self._shown([row["row_id"] for row in rows]),
                index_id=chip["id"], index_type=kind, kit_id=chip["kit_id"],
                kit_fingerprint=chip["kit_fingerprint"])
            assert answer.status_code == 200, answer.text[:300]
            for row in rows:
                self.expected.set_indexes(row["sample_id"], path,
                                          **{kind: index.sequence})

    def clear_one_half_then_drop_again(self, row: dict):
        """Half a clear: a sample whose i7 and i5 are single indexes (not a
        pair) can have one half cleared on its own. The route refuses half of
        a pair, so this path needs a sample built from singles."""
        shown = next(one for one in self.rows() if one["row_id"] == row["row_id"])
        assert shown["i7"] and shown["i5"], "this path needs a sample with both halves"
        answer = self._post(f"/samples/{row['row_id']}/clear-index?index_type=i5",
                            target_indexes=self._shown([row["row_id"]]))
        assert answer.status_code == 200, answer.text[:300]
        self.expected.set_indexes(row["sample_id"], "clear one half, then drop again",
                                  i5="")
        half = next(one for one in self.rows() if one["row_id"] == row["row_id"])
        assert (half["i7"], half["i5"]) == (shown["i7"], ""), (
            f"{self.expected.label}: clearing the i5 left {half}")
        self._drop_single(row, "i5", _COMB_HALF_CLEAR,
                          "clear one half, then drop again")

    def drop_several_at_once(self, rows: list[dict], which=_BULK_PAIRS,
                             path="several indexes dropped at once"):
        """Several chips dragged at once, sent in a shuffled order: the rows
        are filled in the panel's own order, never the click order (CLAUDE.md,
        "Several indexes dropped at once fill the rows in panel order")."""
        kit = self.kits.dual
        panel = page_panel(self.client, kit.kit_id)
        # Only this path's own pairs: a pair another path handed out would put
        # one index on two samples, which the net's collision guard refuses.
        mine = {pair.id for pair in kit.index_pairs[which]}
        choices = [chip for chip in panel if chip["id"] in mine]
        assert len(choices) >= len(rows), (
            f"the panel shows {len(choices)} of this path's own chips, "
            f"{len(rows)} rows need filling")
        chips = self.rng.sample(choices, len(rows))
        in_panel_order = sorted(chips, key=lambda chip: panel.index(chip))
        sent = list(chips)
        self.rng.shuffle(sent)
        if sent == in_panel_order:
            # A shuffle that came out in panel order would hide a server that
            # fills the rows in the order it was sent.
            sent.reverse()
        assert sent != in_panel_order

        answer = self._post(
            "/samples/assign-indexes-bulk",
            start_sample_id=rows[0]["row_id"],
            indexes_json=json.dumps([
                {"id": chip["id"], "type": "pair", "kit_id": chip["kit_id"],
                 "kit_fingerprint": chip["kit_fingerprint"]} for chip in sent]),
            target_sample_ids=json.dumps([row["row_id"] for row in rows]),
            target_indexes=json.dumps([[row["i7"], row["i5"]] for row in rows]),
        )
        assert answer.status_code == 200, answer.text[:300]
        for row, chip in zip(rows, in_panel_order, strict=True):
            # The sequences come from this test's own kit, never from the chip:
            # a chip is the app showing its own stored kit back (review P2-2).
            # chip_for checks the chip against the kit as well.
            pair = next(p for p in kit.index_pairs if p.id == chip["id"])
            assert (chip["i7"], chip["i5"]) == (pair.index1_sequence,
                                                pair.index2_sequence)
            self.expected.set_pair(row["sample_id"], path,
                                   i7=pair.index1_sequence, i5=pair.index2_sequence)

    def drop_from_each_kit_version(self, rows: list[dict]):
        """Two versions of one kit hold the same index names and other
        sequences; a drop names its version by kit id and fingerprint, and the
        sample must get that version's sequences.

        One sample from each version, never one at random: a server that took
        whichever version the database returned first would pass half the
        time."""
        old, new = self.kits.twice_old, self.kits.twice_new
        assert [p.name for p in old.index_pairs] == [p.name for p in new.index_pairs], \
            "the two versions must share their index names"
        for row, kit in zip(rows, (old, new), strict=True):
            pair = kit.index_pairs[0]
            other = (new if kit is old else old).index_pairs[0]
            assert pair.index1_sequence != other.index1_sequence
            chip = self.chip_for(kit, pair.id)
            assert chip["kit_id"] == kit.kit_id
            self._drop(row["row_id"], chip)
            self.expected.set_pair(row["sample_id"],
                                   "a drop from one of two kit versions",
                                   i7=pair.index1_sequence, i5=pair.index2_sequence)

    def clear_then_drop_again(self, row: dict):
        answer = self._post(f"/samples/{row['row_id']}/clear-index",
                            target_indexes=self._shown([row["row_id"]]))
        assert answer.status_code == 200, answer.text[:300]
        self.expected.clear_indexes(row["sample_id"], "clear, then drop again")
        cleared = next(one for one in self.rows() if one["row_id"] == row["row_id"])
        assert (cleared["i7"], cleared["i5"]) == ("", ""), (
            f"the page still shows an index on the row that was cleared: {cleared}")
        pair = self.kits.dual.index_pairs[_CLEARED_PAIR]
        self._drop(row["row_id"], self.chip_for(self.kits.dual, pair.id))
        self.expected.set_pair(row["sample_id"], "clear, then drop again",
                               i7=pair.index1_sequence, i5=pair.index2_sequence)

    def drop_onto_an_assigned_sample(self, row: dict):
        """Replace while editing: the page confirms, then sends the same drop
        with what the row shows (``replaceDropConfirmed`` in app.js)."""
        shown = next(one for one in self.rows() if one["row_id"] == row["row_id"])
        assert shown["i7"], "this path needs a row that already has an index"
        pair = self.kits.dual.index_pairs[_REPLACING_PAIR]
        assert pair.index1_sequence != shown["i7"]
        self._drop(row["row_id"], self.chip_for(self.kits.dual, pair.id))
        self.expected.set_pair(row["sample_id"], "drop onto an assigned sample",
                               i7=pair.index1_sequence, i5=pair.index2_sequence)

    def fill_in_order(self):
        """"Fill empty samples in order", from a non-default Start at: Preview,
        then Assign the plan the preview showed. Always last of the assign
        paths -- it is the one whose rows are "every sample with no index"."""
        waiting = [row["sample_id"] for row in self.unindexed()]
        assert waiting, "the fill has nothing to fill"
        # The page says which rows have no index; the map must say the same,
        # or a sample whose index went missing earlier would be refilled here
        # and the map quietly updated to agree (review P2-4).
        assert set(waiting) == {name for name, row in self.expected.samples.items()
                                if not row["i7"] and not row["i5"]}, (
            f"{self.expected.label}: the page and the map disagree about which "
            f"samples have no index")
        kit = self.kits.fill
        start = kit.index_pairs[2]  # not the kit's first: a non-default Start at
        shown = self._post("/index-fill/preview", selected_kit=kit.kit_id,
                           start_id=start.id)
        assert shown.status_code == 200, shown.text[:300]
        plan = re.search(r'name="plan" value="([^"]*)"', shown.text)
        assert plan, f"the fill preview offers no Assign: {shown.text[:400]}"

        # The preview's own table, as the page shows it: sample, index name,
        # i7, i5 -- compared with what this test's kit holds.
        previewed = re.findall(
            r"<tr>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*"
            r"<td><code>([^<]*)</code></td>\s*<td><code>([^<]*)</code></td>",
            shown.text)
        expected_fill = list(zip(waiting, kit.index_pairs[2:2 + len(waiting)], strict=True))
        assert [(name, pair.name, pair.index1_sequence, pair.index2_sequence)
                for name, pair in expected_fill] == previewed, (
            f"{self.expected.label}: the fill preview shows {previewed[:4]}, this test "
            f"expected {[(n, p.name) for n, p in expected_fill][:4]}")

        # The hidden input's value is HTML-escaped; the fill's signature holds
        # quotes, so send back what the browser would.
        answer = self._post("/index-fill", selected_kit=kit.kit_id, start_id=start.id,
                            plan=html.unescape(plan.group(1)))
        assert answer.status_code == 200, answer.text[:300]
        for name, pair in expected_fill:
            self.expected.set_pair(name, "fill in order",
                                   i7=pair.index1_sequence, i5=pair.index2_sequence)

    # -- lanes ---------------------------------------------------------

    def set_lanes_on_a_subset(self):
        """Several lanes for a subset of samples, so some samples get more
        than one lane. The ticked-rows group is left alone: those samples
        share one index, so they must stay in different lanes."""
        free = [row for row in self.rows()
                if row["sample_id"] not in self.one_index_group]
        assert len(free) >= 2
        how_many = max(2, len(free) // 3)
        chosen = self.rng.sample(free, how_many)
        lanes = self._some_lanes(min(self.lanes, self.rng.choice([2, 3])))
        answer = self._post("/samples/set-lanes",
                            sample_ids=json.dumps([row["row_id"] for row in chosen]),
                            lanes=json.dumps(lanes))
        assert answer.status_code == 200, answer.text[:300]
        for row in chosen:
            self.expected.set_lanes(row["sample_id"], lanes, "set lanes on a subset")

    # -- edits that must move no index ---------------------------------

    def rename_some(self):
        chosen = self.rng.sample(self.rows(), min(3, len(self.rows())))
        for row in chosen:
            new = f"{row['sample_id']}-R"
            answer = self._post(f"/samples/{row['row_id']}", sample_id=new)
            assert answer.status_code == 200, answer.text[:300]
            self.expected.rename(row["sample_id"], new, "rename a sample")
            if row["sample_id"] in self.one_index_group:
                # The samples that share one index are named by sample ID, so
                # a rename has to follow them: delete_some leaves the group
                # whole.
                self.one_index_group.discard(row["sample_id"])
                self.one_index_group.add(new)

    def delete_some(self):
        rows = self.rows()
        # Keep the ticked-rows group whole: it is the net's one group of
        # samples that share an index, and the multiset check needs all of it.
        free = [row for row in rows if row["sample_id"] not in self.one_index_group]
        chosen = self.rng.sample(free, min(2, len(free)))
        answer = self._post("/samples/bulk-delete",
                            sample_ids=json.dumps([row["row_id"] for row in chosen]))
        assert answer.status_code == 200, answer.text[:300]
        for row in chosen:
            self.expected.remove(row["sample_id"], "delete samples")

    def delete_one_by_hand(self):
        """The row's own trash button: DELETE /runs/{id}/samples/{sid}. Which
        sample every later row is depends on it (review P2-6)."""
        free = [row for row in self.rows()
                if row["sample_id"] not in self.one_index_group]
        row = self.rng.choice(free)
        answer = self.client.delete(
            f"/runs/{self.run_id}/samples/{row['row_id']}", headers=ORIGIN)
        assert answer.status_code == 200, answer.text[:300]
        self.expected.remove(row["sample_id"], "delete one sample by hand")

    def set_the_test(self):
        """Every sample gets the net's test, so the sheet plan finds a profile
        for each one."""
        rows = self.rows()
        answer = self._post("/samples/set-test-id",
                            sample_ids=json.dumps([row["row_id"] for row in rows]),
                            test_id=TEST_ID, test_version=TEST_VERSION)
        assert answer.status_code == 200, answer.text[:300]
        self.expected.note("set the test")

    def set_the_mismatches(self):
        """The run's own numbers, written onto the samples themselves.

        Not another number: 2 would raise the collision threshold above the
        distance the net's own indexes keep, and any number other than the
        run's withholds the v1 sheet ("were checked with mismatch numbers
        other than the run's", ``SampleSheetV1Exporter.withheld``) -- and the
        net wants to read that sheet.
        """
        chosen = self.rng.sample(self.rows(), max(1, len(self.rows()) // 4))
        answer = self._post("/samples/set-mismatches",
                            sample_ids=json.dumps([row["row_id"] for row in chosen]),
                            mismatch_index1="1", mismatch_index2="1")
        assert answer.status_code == 200, answer.text[:300]
        self.expected.note("set the barcode mismatches")

    def set_the_override_cycles(self):
        """A value that masks nothing: a masked tail would shorten the indexes
        the collision check compares."""
        chosen = self.rng.sample(self.rows(), max(1, len(self.rows()) // 4))
        answer = self._post("/samples/set-override-cycles",
                            sample_ids=json.dumps([row["row_id"] for row in chosen]),
                            override_cycles=f"Y151;I{INDEX_LENGTH};I{INDEX_LENGTH};Y151")
        assert answer.status_code == 200, answer.text[:300]
        self.expected.note("set the override cycles")

    # -- build ---------------------------------------------------------

    def build(self):
        """Every path, in a shuffled order where the order is free."""
        blocks = self._share_out(self.how_many)
        making = [
            lambda: self.paste_with_indexes(blocks["paste indexed"]),
            lambda: self.paste_from_a_file(blocks["paste file"]),
            lambda: self.paste_without_indexes(blocks["paste plain"]),
            lambda: self.lims_import(blocks["lims indexed"], True, "W-INDEXED"),
            lambda: self.lims_import(blocks["lims plain"], False, "W-PLAIN"),
            lambda: self.add_by_hand(blocks["by hand"]),
        ]
        self.rng.shuffle(making)
        for step in making:
            step()
        assert len(self.rows()) == self.how_many, (
            f"the net meant to make {self.how_many} samples, the page shows "
            f"{len(self.rows())}")

        # Four rows of their own, so clear-and-drop-again,
        # drop-onto-an-assigned-sample and the single-index-onto-a-pair drop
        # each own one.
        seeds = self.unindexed()[:4]
        assert len(seeds) == 4, "the net needs four samples with no index to start"
        self.drop_one_pair(seeds)
        _plain, to_clear, to_replace, to_lose_its_pair = seeds

        # The sample built from single indexes, which the half-clear needs.
        from_singles = self.unindexed()[0]
        self.drop_an_i7_and_an_i5(from_singles)

        ticked = max(2, min(3, self.lanes))
        assigning = [
            lambda: self.drop_on_ticked_rows(self.unindexed()[:ticked]),
            lambda: self.drop_one_single_index_on_ticked_rows(self.unindexed()[:2]),
            lambda: self.drop_several_at_once(self._a_stretch_to_fill()),
            lambda: self.drop_from_each_kit_version(self.unindexed()[:2]),
            lambda: self.clear_then_drop_again(to_clear),
            lambda: self.clear_one_half_then_drop_again(from_singles),
            lambda: self.drop_onto_an_assigned_sample(to_replace),
            lambda: self.drop_a_single_index_onto_a_pair(to_lose_its_pair),
            lambda: self.set_lanes_on_a_subset(),
        ]
        self.rng.shuffle(assigning)
        for step in assigning:
            step()
        self.fill_in_order()
        # Now every row carries an index, so a several-index drop can replace.
        self.drop_several_at_once(self._a_stretch_already_filled(),
                                  which=_BULK_AGAIN_PAIRS,
                                  path="several indexes dropped onto assigned rows")

        quiet = [self.rename_some, self.delete_some, self.delete_one_by_hand,
                 self.set_the_mismatches, self.set_the_override_cycles]
        self.rng.shuffle(quiet)
        for step in quiet:
            step()
        self.set_the_test()  # last: every sample, however it arrived

        self.expected.check_page({row["sample_id"]: row for row in self.rows()})
        self.expected.assert_no_lane_shares_an_index()

    #: The fewest samples a making path contributes. The two paths that make
    #: samples with no index give more, because every assign path takes its
    #: own rows from them and the fill takes what is left.
    _FEWEST = {"paste indexed": 3, "paste file": 3, "paste plain": 9,
               "lims indexed": 3, "lims plain": 9}

    def _share_out(self, total: int) -> dict:
        """How many samples each making path contributes: its fewest, plus a
        random share of what is left over. Giving each path a random share of
        the whole and then raising it to its fewest could leave the last path
        below its own (the soak's seeds 10 and 15)."""
        by_hand = self.rng.randint(1, 3)
        spare = total - by_hand - sum(self._FEWEST.values())
        assert spare >= 0, (
            f"{total} samples is too few: the making paths need "
            f"{sum(self._FEWEST.values()) + by_hand}")
        shares = [self.rng.random() for _ in range(len(self._FEWEST))]
        extra = [int(spare * share / sum(shares)) for share in shares]
        extra[0] += spare - sum(extra)
        counts = {name: fewest + more
                  for (name, fewest), more in zip(self._FEWEST.items(), extra,
                                                  strict=True)}
        assert sum(counts.values()) + by_hand == total, counts
        return dict(counts, **{"by hand": by_hand})

    # -- Ready, then the sheets ----------------------------------------

    def mark_ready(self):
        answer = mark_ready(self.client, self.run_id, ORIGIN)
        assert answer.status_code == 200, answer.text[:400]
        stored = self.ctx.run_repo.get_by_id(self.run_id)
        assert stored.status == RunStatus.READY, (
            f"{self.expected.label}: Mark Ready refused the run: {answer.text[:600]}")

    def edit_after_ready_then_ready_again(self):
        """READY -> DRAFT -> one drop -> READY: the correction a lab makes when
        it spots a wrong index after marking a run Ready. READY->DRAFT clears
        the pre-generated exports, so the second Ready must write new sheets;
        a re-promotion that adopted the old blobs would serve the index the
        operator just replaced (CLAUDE.md, run state integrity; review P2-6)."""
        back = self.client.post(f"/runs/{self.run_id}/status/draft", headers=ORIGIN)
        assert back.status_code == 200, back.text[:300]
        stored = self.ctx.run_repo.get_by_id(self.run_id)
        assert stored.status == RunStatus.DRAFT, "the run did not go back to Draft"
        assert nothing_stored(self.ctx, stored), (
            "READY->DRAFT must clear the stored sheets")

        row = next(one for one in self.rows()
                   if one["i7"] and one["sample_id"] not in self.one_index_group)
        pair = self.kits.dual.index_pairs[_REPROMOTED_PAIR]
        assert pair.index1_sequence != row["i7"]
        self._drop(row["row_id"], self.chip_for(self.kits.dual, pair.id))
        self.expected.set_pair(row["sample_id"], "a drop after Ready, then Ready again",
                               i7=pair.index1_sequence, i5=pair.index2_sequence)
        self.expected.assert_no_lane_shares_an_index()
        self.mark_ready()

    def rename_one_in_the_copy(self, copy_id: str, copy_expected):
        """One edit on the copy before it is marked Ready, so its sheets cannot
        be byte-equal to the source's: that is what tells a sheet the copy
        generated from one it inherited (review P3)."""
        hold_edit_lock(self.ctx, copy_id)
        rows = page_rows(self.client, copy_id)
        row = next(one for one in rows
                   if one["sample_id"] not in self.one_index_group)
        new = f"{row['sample_id']}-C"
        answer = self.client.post(f"/runs/{copy_id}/samples/{row['row_id']}",
                                  data={"sample_id": new}, headers=ORIGIN)
        assert answer.status_code == 200, answer.text[:300]
        copy_expected.rename(row["sample_id"], new, "an edit on the copy")

    def duplicate(self) -> str:
        """A copy of the Ready run, as "Re-run" makes it: a fresh Draft with
        the same samples."""
        answer = self.client.post(f"/runs/{self.run_id}/duplicate",
                                  data={"include_samples": "true"},
                                  headers=ORIGIN, follow_redirects=False)
        assert answer.status_code == 303, answer.text[:300]
        copy_id = answer.headers["location"].rsplit("/", 1)[-1]
        self.expected.note(_COPY_PATH)
        return copy_id


def _bearer(client, ctx):
    return {"Authorization": f"Bearer {_token(ctx)}"}


def _read_sheets(client, headers, run_id: str, expected, direction) -> int:
    """Fetch the stored sheets and the JSON through the Bearer API and compare
    every row to the map. Returns the number of rows checked."""
    checked = 0
    v2 = client.get(f"/api/runs/{run_id}/samplesheet-v2", headers=headers)
    assert v2.status_code == 200, v2.text[:300]
    checked += expected.check_sheet(v2.text, "v2", direction["v2"])

    v1 = client.get(f"/api/runs/{run_id}/samplesheet-v1", headers=headers)
    if direction["v1"] is None:
        assert v1.status_code == 404, (
            f"{expected.label}: this instrument writes no v1 sheet, but the API "
            f"served one")
    else:
        assert v1.status_code == 200, v1.text[:300]
        checked += expected.check_sheet(v1.text, "v1", direction["v1"])

    payload = client.get(f"/api/runs/{run_id}/json", headers=headers)
    assert payload.status_code == 200, payload.text[:300]
    checked += expected.check_json(payload.json(), direction["v2"])
    return checked


def _assert_every_path_was_used(expected):
    missing = [path for path in ALL_PATHS if not expected.paths.get(path)]
    assert not missing, (
        f"{expected.label}: the net never used {missing}. A path nobody walks "
        f"proves nothing.")


def _assert_the_i5_rule_bites(expected, sheet: str, direction: str, label: str):
    """The Index2 column really is the direction the table says, on a row
    where the two directions differ."""
    telling = [row for row in expected.samples.values()
               if row["i5"] and reverse_complement(row["i5"]) != row["i5"]]
    assert telling, f"{label}: every i5 in this run is its own reverse complement"
    section = next(one for one in data_sections(sheet) if "i5" in one.roles)
    written = {section.cell(row, "sample_id"): section.cell(row, "i5")
               for row in section.rows}
    told = 0
    for name, row in expected.samples.items():
        if not row["i5"] or reverse_complement(row["i5"]) == row["i5"]:
            continue
        found = written.get(name)
        if direction == AS_ENTERED:
            assert found == row["i5"] and found != reverse_complement(row["i5"]), \
                f"{label}: {name}'s Index2 is {found!r}, not the i5 as entered"
        else:
            assert found == reverse_complement(row["i5"]) and found != row["i5"], \
                f"{label}: {name}'s Index2 is {found!r}, not the i5 reversed"
        told += 1
    assert told, f"{label}: no row could tell the two i5 directions apart"


# --------------------------------------------------------------------------
# The tests
# --------------------------------------------------------------------------

class TestTheNetsOwnTools:
    """A net built on a broken oracle proves nothing, so the oracle is
    checked first."""

    def test_the_nets_own_sequences_are_far_apart(self):
        """Every sequence the net can hand out differs from every other in at
        least MIN_INDEX_DISTANCE bases, so two of the net's own samples never
        collide however the lanes fall -- and none of them starts, in either
        read direction, with the two dark bases the checks refuse."""
        assert len(set(POOL)) == len(POOL) >= 800
        assert all(len(word) == INDEX_LENGTH for word in POOL)
        assert all(usable(word) for word in POOL)
        worst = min(hamming(POOL[i], POOL[j])
                    for i in range(len(POOL))
                    for j in range(i + 1, len(POOL)))
        assert worst >= MIN_INDEX_DISTANCE, worst

    def test_the_i7_and_i5_halves_never_meet(self):
        sequences = Sequences()
        i7s = set(sequences.i7(400))
        i5s = set(sequences.i5(400))
        assert len(i7s) == len(i5s) == 400
        assert not (i7s & i5s)

    def test_the_reverse_complement(self):
        assert reverse_complement("ATTACTCG") == "CGAGTAAT"
        assert reverse_complement("TATAGCCT") == "AGGCTATA"
        assert reverse_complement(reverse_complement("ACGTTGCA")) == "ACGTTGCA"

    def test_the_default_seeds_reach_every_case(self):
        """Each default seed picks a different run, so every instrument and i5
        workflow in CASES really is built and marked Ready."""
        if os.environ.get("SEQSETUP_SAFETY_NET_SEEDS", "").strip():
            pytest.skip("a soak was asked for; it picks its own seeds")
        assert {seed % len(CASES) for seed in _seeds()} == set(range(len(CASES)))

    def test_the_i5_table_holds_both_directions(self):
        """One instrument writes Index2 as entered and one reverses it, so a
        flipped i5 rule cannot pass the net."""
        used = {I5_SHEET_DIRECTION[(case[1].value, case[3])]["v2"] for case in CASES}
        assert used == {AS_ENTERED, REVERSE_COMPLEMENT}
        v1 = {I5_SHEET_DIRECTION[(case[1].value, case[3])]["v1"] for case in CASES}
        assert {AS_ENTERED, REVERSE_COMPLEMENT} <= v1

    def test_the_sheet_reader_finds_the_sections_and_the_columns(self):
        sheet = ("[Header]\nFileFormatVersion,2\n\n"
                 "[BCLConvert_Data]\nLane,Sample_ID,Index,Index2\n"
                 "1,S1,AAAACCCC,GGGGTTTT\n\n"
                 "[Cloud_Data]\nSample_ID,ProjectName,LibraryName\n"
                 "S1,P,S1_AAAACCCC_GGGGTTTT\n\n")
        names = [section.name for section in data_sections(sheet)]
        assert names == ["[BCLConvert_Data]", "[Cloud_Data]"]
        bcl = data_sections(sheet)[0]
        assert bcl.roles == {"lane": 0, "sample_id": 1, "i7": 2, "i5": 3}
        assert bcl.cell(bcl.rows[0], "i5") == "GGGGTTTT"

    def test_a_sheet_that_lost_every_row_is_not_a_pass(self):
        """The vacuity guard: a header with no data row must fail, not pass."""
        expected = Expected("empty sheet")
        expected.add("S1", [1], "paste index columns", i7="AAAACCCC", i5="GGGGTTTT")
        sheet = "[BCLConvert_Data]\nLane,Sample_ID,Index,Index2\n\n"
        with pytest.raises(AssertionError):
            expected.check_sheet(sheet, "v2", AS_ENTERED)


@pytest.mark.parametrize("seed", _seeds())
def test_no_sample_gets_another_samples_index(seed, logged_in_client, fresh_app,
                                              monkeypatch):
    """Build a run by every path, mark it Ready, and read the stored sheets
    back through the API: every row holds the index and the lane the test gave
    that sample, and the rows are one per (sample, lane)."""
    _app, ctx, _db = fresh_app
    rng = random.Random(seed)
    case = CASES[seed % len(CASES)]
    how_many = rng.randint(40, 96)

    net = Net(logged_in_client, ctx, monkeypatch, seed, case, how_many)
    net.build()
    net.mark_ready()

    headers = _bearer(logged_in_client, ctx)
    # One snapshot of the map per Ready run, so the row count below is taken
    # from the map each sheet was read against.
    maps = [net.expected.copy(f"{net.expected.label} at its first Ready")]
    checked = _read_sheets(logged_in_client, headers, net.run_id, net.expected,
                           net.direction)

    v2 = logged_in_client.get(f"/api/runs/{net.run_id}/samplesheet-v2",
                              headers=headers).text
    _assert_the_i5_rule_bites(net.expected, v2, net.direction["v2"],
                              net.expected.label)

    # Back to Draft, one index replaced, Ready again: the second Ready's sheets
    # must hold the new index, never the one it replaced.
    net.edit_after_ready_then_ready_again()
    after = net.expected.copy(f"{net.expected.label} at its second Ready")
    maps.append(after)
    checked += _read_sheets(logged_in_client, headers, net.run_id, after,
                            net.direction)

    # A copy of the run, with one sample renamed, marked Ready too: its sheets
    # must match the copy's own map.
    copy_id = net.duplicate()
    copy_expected = net.expected.copy(f"{net.expected.label} copy")
    net.rename_one_in_the_copy(copy_id, copy_expected)
    assert mark_ready(logged_in_client, copy_id, ORIGIN).status_code == 200
    assert ctx.run_repo.get_by_id(copy_id).status == RunStatus.READY
    maps.append(copy_expected)
    checked += _read_sheets(logged_in_client, headers, copy_id, copy_expected,
                            net.direction)

    # Vacuity guards.
    _assert_every_path_was_used(net.expected)
    assert checked > 0
    wanted = sum(_expected_row_count(one, net.direction) for one in maps)
    assert checked == wanted, f"{net.expected.label}: checked {checked} rows, {wanted} wanted"
    assert any(len(row["lanes"]) > 1 for row in net.expected.samples.values()), (
        f"{net.expected.label}: no sample has more than one lane")


def _expected_row_count(one, direction) -> int:
    """How many rows one map's run must have had compared: the sections with a
    Lane column hold one row per (sample, lane), the others one per sample, and
    the JSON export one entry per sample.

    Counted from the map and the sections a sheet has, never from what the
    checker read."""
    with_lane = sum(one.rows_with_a_lane().values())
    without = sum(one.rows_without_a_lane().values())
    total = with_lane   # [BCLConvert_Data]: a Lane column
    total += without    # [Cloud_Data]: no Lane column
    if direction["v1"] is not None:
        total += with_lane  # the v1 [Data] section
    total += without        # the JSON export's samples
    return total


def test_both_i5_directions_reach_a_stored_sheet(logged_in_client, fresh_app,
                                                 monkeypatch):
    """The net's small twin: the same two samples on an instrument that writes
    Index2 as entered and on one that reverses it. Without this, a seed that
    only ever picked one instrument would leave a flipped i5 rule unseen."""
    _app, ctx, _db = fresh_app
    _seed_profiles(ctx)
    sequences = Sequences()
    (i7_one, i5_one), (i7_two, i5_two) = sequences.pairs(2)
    assert reverse_complement(i5_one) != i5_one
    headers = _bearer(logged_in_client, ctx)
    seen = {}

    for case in (CASES[0], CASES[1]):
        case_id, instrument, flowcell, workflow, _lanes = case
        run_id = f"i5-direction-{case_id}"
        run = SequencingRun(
            id=run_id, run_name=f"i5 {case_id}", instrument_platform=instrument,
            flowcell_type=flowcell, i5_workflow=workflow,
            run_cycles=RunCycles(151, 151, INDEX_LENGTH, INDEX_LENGTH))
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run_id)
        expected = Expected(f"i5 direction {case_id}")
        paste = ("sample_id\tindex_i7\tindex_i5\n"
                 f"D-01\t{i7_one}\t{i5_one}\n"
                 f"D-02\t{i7_two}\t{i5_two}\n")
        added = logged_in_client.post(
            f"/runs/{run_id}/samples/bulk",
            data={"paste_data": paste, "lanes": ["1"],
                  "default_test_id": TEST_ID, "default_test_version": TEST_VERSION},
            headers=ORIGIN)
        assert added.status_code == 200 and "rejected" not in added.text, added.text[:400]
        expected.add("D-01", [1], "paste index columns", i7=i7_one, i5=i5_one)
        expected.add("D-02", [1], "paste index columns", i7=i7_two, i5=i5_two)

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.READY
        direction = I5_SHEET_DIRECTION[(instrument.value, workflow)]
        sheet = logged_in_client.get(f"/api/runs/{run_id}/samplesheet-v2",
                                     headers=headers)
        assert sheet.status_code == 200
        assert expected.check_sheet(sheet.text, "v2", direction["v2"]) > 0
        _assert_the_i5_rule_bites(expected, sheet.text, direction["v2"], expected.label)
        section = next(one for one in data_sections(sheet.text) if "i5" in one.roles)
        seen[case_id] = section.cell(section.rows[0], "i5")

    assert seen[CASES[0][0]] == i5_one, "this instrument must write the i5 as entered"
    assert seen[CASES[1][0]] == reverse_complement(i5_one), \
        "this instrument must write the i5 reversed"
    assert seen[CASES[0][0]] != seen[CASES[1][0]]


def test_a_paste_may_not_carry_a_lane_column(logged_in_client, fresh_app):
    """A sample's lanes never come from a paste: a Lane column is refused,
    naming it. The net sets lanes from the Lanes picker, the LIMS import's
    picked lanes, and set-lanes -- and this pins that there is no fourth way
    hidden in the paste."""
    _app, ctx, _db = fresh_app
    run_id = "paste-lane-column"
    ctx.run_repo.save(SequencingRun(
        id=run_id, run_name="Lane column", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, INDEX_LENGTH, INDEX_LENGTH)))
    hold_edit_lock(ctx, run_id)
    i7, i5 = Sequences().pairs(1)[0]

    answer = logged_in_client.post(
        f"/runs/{run_id}/samples/bulk",
        data={"paste_data": f"sample_id\tindex_i7\tindex_i5\tLane\nL-01\t{i7}\t{i5}\t2\n",
              "lanes": ["1"]},
        headers=ORIGIN)

    assert "SeqSetup does not read these" in answer.text.replace("&quot;", '"')
    assert ctx.run_repo.get_by_id(run_id).samples == []
