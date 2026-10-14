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
or ``_LANE_PATHS`` below, or the net will not cover it.

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

from .conftest import hold_edit_lock, mark_ready
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
    "LIMS index fields",
    "one drop: a pair",
    "one drop: an i7",
    "one drop: an i5",
    "drop on ticked rows",
    "several indexes dropped at once",
    "a drop from one of two kit versions",
    "clear, then drop again",
    "drop onto an assigned sample",
    "fill in order",
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
_SEED_PAIRS = slice(0, 3)      # one single drop each, to start the run off
_TICKED_PAIR = 3               # one index on every ticked row
_CLEARED_PAIR = 4              # dropped again after a clear
_REPLACING_PAIR = 5            # dropped onto a sample that already has one
_BULK_PAIRS = slice(6, None)   # several dropped at once


def _seeds() -> list[int]:
    """The default seeds, or the soak's (``SEQSETUP_SAFETY_NET_SEEDS``)."""
    asked = os.environ.get("SEQSETUP_SAFETY_NET_SEEDS", "").strip()
    if not asked:
        return [11, 404, 9001]
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
        rows.append({
            "row_id": found.group("row_id"),
            "sample_id": shown_id.group(1) if shown_id else "",
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

    def _some_lanes(self, how_many: int) -> list[int]:
        return sorted(self.rng.sample(range(1, self.lanes + 1), how_many))

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
        answer = self._post(f"/samples/{row_id}/assign-index", **values)
        assert answer.status_code == 200, answer.text[:300]

    # -- the paths that make samples -----------------------------------

    def paste_with_indexes(self, how_many: int):
        """A paste whose header names the index columns; Preview, then Add.
        A paste never carries a lane column -- the lanes come from the Lanes
        picker (``services/sample_parser.py``), and the net proves that in
        ``test_a_paste_may_not_carry_a_lane_column``."""
        lanes = self._some_lanes(self.rng.choice([1, 2]))
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
        lanes = self._some_lanes(self.rng.choice([1, 2]))
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

    def drop_an_i7_and_an_i5(self, row: dict):
        """A single i7 and a single i5 from a combinatorial kit."""
        kit = self.kits.comb
        i7 = kit.i7_indexes[self.rng.randrange(len(kit.i7_indexes))]
        i5 = kit.i5_indexes[self.rng.randrange(len(kit.i5_indexes))]
        self._drop(row["row_id"], self.chip_for(kit, f"{kit.name}_i7_{i7.name}", "i7"))
        self.expected.set_indexes(row["sample_id"], "one drop: an i7", i7=i7.sequence)
        self._drop(row["row_id"], self.chip_for(kit, f"{kit.name}_i5_{i5.name}", "i5"))
        self.expected.set_indexes(row["sample_id"], "one drop: an i5", i5=i5.sequence)

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
                            index_pair_id=chip["id"], kit_id=chip["kit_id"],
                            kit_fingerprint=chip["kit_fingerprint"])
        assert answer.status_code == 200, answer.text[:300]
        for row in rows:
            self.expected.set_pair(row["sample_id"], "drop on ticked rows",
                                   i7=pair.index1_sequence, i5=pair.index2_sequence)

    def drop_several_at_once(self, rows: list[dict]):
        """Several chips dragged at once, sent in a shuffled order: the rows
        are filled in the panel's own order, never the click order (CLAUDE.md,
        "Several indexes dropped at once fill the rows in panel order")."""
        kit = self.kits.dual
        panel = page_panel(self.client, kit.kit_id)
        # Only this path's own pairs: a pair another path handed out would put
        # one index on two samples, which the net's collision guard refuses.
        mine = {pair.id for pair in kit.index_pairs[_BULK_PAIRS]}
        choices = [chip for chip in panel if chip["id"] in mine]
        chips = self.rng.sample(choices, len(rows))
        in_panel_order = sorted(chips, key=lambda chip: panel.index(chip))
        sent = list(chips)
        self.rng.shuffle(sent)

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
            self.expected.set_pair(row["sample_id"], "several indexes dropped at once",
                                   i7=chip["i7"], i5=chip["i5"])

    def drop_from_one_kit_version(self, row: dict):
        """Two versions of one kit hold the same index names and other
        sequences; the drop names a version by kit id and fingerprint, and the
        sample must get that version's sequences."""
        old, new = self.kits.twice_old, self.kits.twice_new
        pair_old = old.index_pairs[0]
        pair_new = new.index_pairs[0]
        assert pair_old.name == pair_new.name, "the two versions must share a name"
        assert pair_old.index1_sequence != pair_new.index1_sequence
        kit = self.rng.choice([old, new])
        pair = kit.index_pairs[0]
        chip = self.chip_for(kit, pair.id)
        assert chip["kit_id"] == kit.kit_id
        self._drop(row["row_id"], chip)
        self.expected.set_pair(row["sample_id"], "a drop from one of two kit versions",
                               i7=pair.index1_sequence, i5=pair.index2_sequence)

    def clear_then_drop_again(self, row: dict):
        answer = self._post(f"/samples/{row['row_id']}/clear-index")
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

        # Three rows of their own, so clear-and-drop-again and
        # drop-onto-an-assigned-sample each own one.
        seeds = self.unindexed()[:3]
        assert len(seeds) == 3, "the net needs three samples with no index to start"
        self.drop_one_pair(seeds)
        plain, to_clear, to_replace = seeds

        ticked = max(2, min(3, self.lanes))
        assigning = [
            lambda: self.drop_an_i7_and_an_i5(self.unindexed()[0]),
            lambda: self.drop_on_ticked_rows(self.unindexed()[:ticked]),
            lambda: self.drop_several_at_once(
                self.longest_unindexed_stretch()[:self.rng.randint(3, 6)]),
            lambda: self.drop_from_one_kit_version(self.unindexed()[0]),
            lambda: self.clear_then_drop_again(to_clear),
            lambda: self.drop_onto_an_assigned_sample(to_replace),
            lambda: self.set_lanes_on_a_subset(),
        ]
        self.rng.shuffle(assigning)
        for step in assigning:
            step()
        self.fill_in_order()

        quiet = [self.rename_some, self.delete_some, self.set_the_mismatches,
                 self.set_the_override_cycles]
        self.rng.shuffle(quiet)
        for step in quiet:
            step()
        self.set_the_test()  # last: every sample, however it arrived

        self.expected.check_page({row["sample_id"]: row for row in self.rows()})
        self.expected.assert_no_lane_shares_an_index()

    def _share_out(self, total: int) -> dict:
        """How many samples each making path contributes."""
        by_hand = self.rng.randint(1, 3)
        rest = total - by_hand
        shares = [self.rng.random() for _ in range(4)]
        scale = rest / sum(shares)
        counts = [max(3, int(share * scale)) for share in shares]
        counts[0] += rest - sum(counts)
        assert counts[0] >= 3, "the net could not share out its samples"
        return {"paste indexed": counts[0], "paste plain": counts[1],
                "lims indexed": counts[2], "lims plain": counts[3],
                "by hand": by_hand}

    # -- Ready, then the sheets ----------------------------------------

    def mark_ready(self):
        answer = mark_ready(self.client, self.run_id, ORIGIN)
        assert answer.status_code == 200, answer.text[:400]
        stored = self.ctx.run_repo.get_by_id(self.run_id)
        assert stored.status == RunStatus.READY, (
            f"{self.expected.label}: Mark Ready refused the run: {answer.text[:600]}")

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
    for name, row in expected.samples.items():
        if row["i5"] and reverse_complement(row["i5"]) != row["i5"]:
            found = written.get(name)
            if direction == AS_ENTERED:
                assert found == row["i5"] and found != reverse_complement(row["i5"])
            else:
                assert found == reverse_complement(row["i5"]) and found != row["i5"]
            return
    raise AssertionError(f"{label}: no row could tell the two i5 directions apart")


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
    checked = _read_sheets(logged_in_client, headers, net.run_id, net.expected,
                           net.direction)

    v2 = logged_in_client.get(f"/api/runs/{net.run_id}/samplesheet-v2",
                              headers=headers).text
    _assert_the_i5_rule_bites(net.expected, v2, net.direction["v2"],
                              net.expected.label)

    # A copy of the run, marked Ready too: its sheets must match the same map.
    copy_id = net.duplicate()
    copy_expected = net.expected.copy(f"{net.expected.label} copy")
    assert mark_ready(logged_in_client, copy_id, ORIGIN).status_code == 200
    assert ctx.run_repo.get_by_id(copy_id).status == RunStatus.READY
    checked += _read_sheets(logged_in_client, headers, copy_id, copy_expected,
                            net.direction)

    # Vacuity guards.
    _assert_every_path_was_used(net.expected)
    assert checked > 0
    assert checked == _expected_row_count(net.expected, copy_expected, net.direction), (
        f"{net.expected.label}: checked {checked} rows")
    assert any(len(row["lanes"]) > 1 for row in net.expected.samples.values()), (
        f"{net.expected.label}: no sample has more than one lane")


def _expected_row_count(expected, copy_expected, direction) -> int:
    """How many rows the net must have compared: the sections with a Lane
    column hold one row per (sample, lane), the others one per sample, and the
    JSON export one entry per sample. Both sheets of both runs."""
    total = 0
    for one in (expected, copy_expected):
        with_lane = sum(one.rows_with_a_lane().values())
        without = sum(one.rows_without_a_lane().values())
        total += with_lane  # [BCLConvert_Data]: a Lane column
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
