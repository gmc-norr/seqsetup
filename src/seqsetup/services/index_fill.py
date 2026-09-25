"""Plan "Fill empty samples in order": give each sample that has no index the
next unused index of one kit, in table order.

Pure: reads a run and a kit, returns a plan, changes nothing. The preview
shows a plan; the apply route rebuilds it and saves only when its signature
matches the one the preview showed.
"""

import json
from dataclasses import dataclass, field
from typing import Optional, Union

from ..models.index import Index, IndexKit, IndexPair
from ..models.sequencing_run import SequencingRun

COMBINATORIAL_REFUSAL = (
    "Fill in order works with unique dual and single-index kits. "
    "Assign combinatorial indexes by hand."
)


@dataclass
class KitEntry:
    """One index of a kit, in kit order: a pair (unique dual) or an i7 (single)."""

    id: str  # IndexPair.id, or "<kit name>_i7_<index name>" as the index panel uses
    name: str
    i7: str
    i5: Optional[str]
    well: Optional[str]
    index: Union[IndexPair, Index]


@dataclass
class FillRow:
    sample_id: str  # Sample.id
    sample_label: str  # Sample.sample_id, as the table shows it
    entry: KitEntry


@dataclass
class FillPlan:
    kit: IndexKit
    mode: str  # "pair", "i7", or "" when the kit cannot be filled in order
    entries: list[KitEntry]
    needed: int  # samples with no index at all
    start: Optional[KitEntry] = None
    rows: list[FillRow] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    partial: list[str] = field(default_factory=list)
    problem: str = ""

    @property
    def can_apply(self) -> bool:
        return not self.problem and bool(self.rows)

    def signature(self) -> str:
        """What Assign will save, for the apply route to compare. Holds the
        sequences, not just the index ids: a kit sync can change a sequence
        without changing the kit's name, version or index ids."""
        return json.dumps([
            self.kit.kit_id,
            [[row.sample_id, row.entry.id, row.entry.i7, row.entry.i5] for row in self.rows],
        ])


def kit_entries(kit: IndexKit) -> list[KitEntry]:
    """The kit's indexes in kit order; empty for a combinatorial kit."""
    if kit.is_unique_dual():
        return [
            KitEntry(p.id, p.name, p.index1_sequence, p.index2_sequence, p.well_position, p)
            for p in kit.index_pairs
        ]
    if kit.is_single():
        return [
            KitEntry(f"{kit.name}_i7_{i.name}", i.name, i.sequence, None, i.well_position, i)
            for i in kit.i7_indexes
        ]
    return []


def needs_index(sample) -> bool:
    """Only a sample with no index at all; a partial one is left alone."""
    return sample.index_pair is None and sample.index1 is None and sample.index2 is None


def build_fill_plan(run: SequencingRun, kit: IndexKit, start_id: str = "") -> FillPlan:
    """Plan giving each sample with no index the next unused index of ``kit``.

    An index is skipped when its i7 is already an i7 in the run or its i5 is
    already an i5 in the run; indexes chosen for this fill count as used.
    From the start it goes forward only. If there are not enough, the plan
    has a problem and no rows: nothing is partly filled.

    Raises ValueError when ``start_id`` is given but is not an index of ``kit``.
    """
    mode = "pair" if kit.is_unique_dual() else "i7" if kit.is_single() else ""
    entries = kit_entries(kit)
    targets = [s for s in run.samples if needs_index(s)]
    plan = FillPlan(kit=kit, mode=mode, entries=entries, needed=len(targets))

    if not mode:
        plan.problem = COMBINATORIAL_REFUSAL
        return plan
    if not entries:
        plan.problem = f"{kit.name} has no indexes."
        return plan

    plan.partial = [
        s.sample_id for s in run.samples
        if not needs_index(s) and s.index_pair is None and s.index1 is None
    ]

    used_i7 = {s.index1_sequence for s in run.samples if s.index1_sequence}
    used_i5 = {s.index2_sequence for s in run.samples if s.index2_sequence}

    def used(entry: KitEntry) -> bool:
        return entry.i7 in used_i7 or (entry.i5 is not None and entry.i5 in used_i5)

    if start_id:
        pos = next((i for i, e in enumerate(entries) if e.id == start_id), None)
        if pos is None:
            raise ValueError(f"{start_id!r} is not an index of {kit.name}")
    else:
        pos = next((i for i, e in enumerate(entries) if not used(e)), None)
    if pos is not None:
        plan.start = entries[pos]

    if not targets:
        if plan.partial:
            names = ", ".join(plan.partial[:10])
            if len(plan.partial) > 10:
                names += f", and {len(plan.partial) - 10} more"
            plan.problem = (
                f"Fill in order only fills samples with no index at all. "
                f"{len(plan.partial)} sample(s) have only an i5 index; "
                f"give them an i7 by hand: {names}."
            )
        else:
            plan.problem = "Every sample already has an index."
        return plan
    if pos is None:
        plan.problem = f"Every index in {kit.name} is already used in this run."
        return plan

    chosen: list[KitEntry] = []
    skipped: list[str] = []
    for entry in entries[pos:]:
        if len(chosen) == len(targets):
            break
        if used(entry):
            skipped.append(entry.name)
            continue
        chosen.append(entry)
        used_i7.add(entry.i7)
        if entry.i5 is not None:
            used_i5.add(entry.i5)

    if len(chosen) < len(targets):
        plan.problem = (
            f"Not enough unused indexes: {len(targets)} needed, {len(chosen)} left in "
            f"{kit.name} from {plan.start.name}. Pick an earlier start or another kit."
        )
        return plan

    plan.skipped = skipped
    plan.rows = [FillRow(s.id, s.sample_id, e) for s, e in zip(targets, chosen)]
    return plan
