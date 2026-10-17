"""The grouped collision report reports exactly the collisions the per-pair
scan reported — proved over generated runs against an oracle kept here.

docs/design/2026-10-17-collision-report-grouped-design.md. The report is now
one finding per group of samples sharing one index (or per pair of groups
within the tolerance) instead of one object per colliding pair. The grouping
is only safe if every colliding (sample, sample, lane) triple is still
derivable, so this test expands the grouped report back into triples and
compares the SET with the oracle's, exactly.

The oracle below is the per-pair scan as it stood at main 7c95e76, written out
here so the grouping is compared against an independent implementation. It
deliberately shares ``effective_index_sequence`` and ``hamming_distance`` with
the application: those two are the comparison, which this change does not
touch, and re-deriving OverrideCycles masking in a test would only add a
second place to get it wrong. The comparison itself is driven by
tests/unit/test_validation.py and tests/unit/test_collision_rule.py, which
still call the unchanged per-pair ``validate_index_collisions``.

Run count: ORACLE_RUNS below (fixed seeds, so the same runs every time). The
default is kept low so this file stays a few seconds of the unit suite; set
SEQSETUP_COLLISION_ORACLE_RUNS to sweep more. The deep sweep is run by hand
and its result recorded with the change.
"""

import os
import random
from collections import defaultdict

import pytest

from seqsetup.data.instruments import get_lanes_for_flowcell
from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.index_collision_validator import IndexCollisionValidator
from seqsetup.services.validation import ValidationService, clear_validation_cache
from seqsetup.services.validation_utils import (
    effective_index_sequence,
    hamming_distance,
    reverse_complement,
)


#: Generated runs per sweep. Kept small enough that this file stays a few
#: seconds of the unit suite; the sample counts are drawn so that most runs
#: are small and a few are large.
ORACLE_RUNS = int(os.environ.get("SEQSETUP_COLLISION_ORACLE_RUNS", "600"))

#: Of those, how many also go through the whole ValidationService so the
#: refusal (error_count > 0) is compared, not just the collision set.
FULL_VALIDATE_RUNS = int(os.environ.get("SEQSETUP_COLLISION_ORACLE_FULL", "40"))


# --------------------------------------------------------------------------
# The oracle: the per-pair scan of main 7c95e76.
# --------------------------------------------------------------------------

def _oracle_mismatches(sample1, sample2, run, index_num, mismatches=None):
    if index_num == 1:
        m1 = sample1.barcode_mismatches_index1
        m2 = sample2.barcode_mismatches_index1
        default = run.barcode_mismatches_index1
    else:
        m1 = sample1.barcode_mismatches_index2
        m2 = sample2.barcode_mismatches_index2
        default = run.barcode_mismatches_index2
    m1 = m1 if m1 is not None else default
    m2 = m2 if m2 is not None else default
    if mismatches:
        m1 = mismatches.get((sample1.id, index_num), m1)
        m2 = mismatches.get((sample2.id, index_num), m2)
    return max(m1, m2)


def _oracle_pair_collides(sample1, sample2, run, mismatches=None):
    i7_seq1 = effective_index_sequence(sample1, 1, run)
    i7_seq2 = effective_index_sequence(sample2, 1, run)
    i5_seq1 = effective_index_sequence(sample1, 2, run)
    i5_seq2 = effective_index_sequence(sample2, 2, run)
    if not i7_seq1 or not i7_seq2:
        return False
    i7_distance = hamming_distance(i7_seq1, i7_seq2)
    if i5_seq1 and i5_seq2:
        i5_distance = hamming_distance(i5_seq1, i5_seq2)
        m_i7 = _oracle_mismatches(sample1, sample2, run, 1, mismatches)
        m_i5 = _oracle_mismatches(sample1, sample2, run, 2, mismatches)
        return i7_distance <= 2 * m_i7 and i5_distance <= 2 * m_i5
    m_i7 = _oracle_mismatches(sample1, sample2, run, 1, mismatches)
    return i7_distance <= 2 * m_i7


def oracle_triples(run, instrument_config=None, mismatches=None):
    """Every colliding (sample id, sample id, lane), the ids sorted."""
    total_lanes = get_lanes_for_flowcell(
        run.instrument_platform, run.flowcell_type, instrument_config)
    all_lanes = list(range(1, total_lanes + 1))
    lane_samples = defaultdict(list)
    for sample in run.samples:
        if not sample.has_index:
            continue
        for lane in (sample.lanes or all_lanes):
            lane_samples[lane].append(sample)
    triples = set()
    for lane, samples in lane_samples.items():
        n = len(samples)
        for i in range(n):
            for j in range(i + 1, n):
                if _oracle_pair_collides(samples[i], samples[j], run, mismatches):
                    a, b = sorted((samples[i].id, samples[j].id))
                    triples.add((a, b, lane))
    return triples


# --------------------------------------------------------------------------
# Expanding the grouped report back into triples.
# --------------------------------------------------------------------------

def triples_from_groups(groups):
    """Every colliding (sample id, sample id, lane) the grouped report means.

    A finding with no second set stands for every pair inside its one set; a
    finding with two sets stands for every pair across them. Returns the set
    and the number of pairs expanded, so a caller can check that no pair was
    produced twice.
    """
    triples, produced = set(), 0
    for group in groups:
        if group.sample2_ids:
            for one in group.sample1_ids:
                for other in group.sample2_ids:
                    a, b = sorted((one, other))
                    triples.add((a, b, group.lane))
                    produced += 1
        else:
            ids = group.sample1_ids
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    a, b = sorted((ids[i], ids[j]))
                    triples.add((a, b, group.lane))
                    produced += 1
    return triples, produced


# --------------------------------------------------------------------------
# The generator.
# --------------------------------------------------------------------------

_MODES = ("unique-dual", "combinatorial", "single", "i7-only", "mixed")
_FLOWCELLS = ("1.5B", "10B", "25B")
_WORKFLOWS = ("", "BCLConvert", "DRAGEN", "nonsense-workflow")


def _sample_count(rng):
    """Mostly small runs, a few large ones, 1..400."""
    bucket = rng.random()
    if bucket < 0.70:
        return rng.randint(1, 12)
    if bucket < 0.90:
        return rng.randint(13, 60)
    if bucket < 0.98:
        return rng.randint(61, 150)
    return rng.randint(151, 400)


def _sequence(rng, length):
    return "".join(rng.choice("ACGT") for _ in range(length))


def _near(rng, seq, changes):
    """``seq`` with ``changes`` positions changed (a near-duplicate)."""
    chars = list(seq)
    for position in rng.sample(range(len(seq)), min(changes, len(seq))):
        chars[position] = rng.choice([b for b in "ACGT" if b != chars[position]])
    return "".join(chars)


def generated_run(seed):
    """One random run. The same seed always makes the same run."""
    rng = random.Random(seed)
    n = _sample_count(rng)
    mode = rng.choice(_MODES)
    length = rng.randint(6, 12)
    flowcell = rng.choice(_FLOWCELLS)
    lanes_total = get_lanes_for_flowcell(InstrumentPlatform.NOVASEQ_X, flowcell)
    run = SequencingRun(
        id=f"gen-{seed}", run_name=f"Generated {seed}",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type=flowcell,
        run_cycles=RunCycles(151, 151, rng.choice([8, 10, length]), rng.choice([8, 10, length])),
        barcode_mismatches_index1=rng.choice([0, 1, 2]),
        barcode_mismatches_index2=rng.choice([0, 1, 2]),
        i5_workflow=rng.choice(_WORKFLOWS),
    )
    # A small pool, so duplicates and near-duplicates turn up by themselves.
    pool_size = max(1, min(n, rng.choice([1, 2, 3, n // 4 + 1, n])))
    i7_pool = [_sequence(rng, length) for _ in range(pool_size)]
    i5_pool = [_sequence(rng, length) for _ in range(pool_size)]
    # Plant near-duplicates: sequences 1 or 2 bases away from a pool member.
    for _ in range(rng.randint(0, 3)):
        i7_pool.append(_near(rng, rng.choice(i7_pool), rng.randint(1, 2)))
        i5_pool.append(_near(rng, rng.choice(i5_pool), rng.randint(1, 2)))

    for k in range(n):
        lanes = sorted(rng.sample(range(1, lanes_total + 1),
                                  rng.randint(1, min(lanes_total, 3)))) \
            if rng.random() < 0.85 else []
        sample = Sample(
            id=f"s{seed}-{k}", sample_id=f"PAT{seed}-{k:03d}", lanes=lanes,
            barcode_mismatches_index1=rng.choice([None, 0, 1, 2]),
            barcode_mismatches_index2=rng.choice([None, 0, 1, 2]),
        )
        if mode == "unique-dual":
            i7, i5 = _sequence(rng, length), _sequence(rng, length)
        elif mode == "combinatorial":
            i7, i5 = rng.choice(i7_pool), rng.choice(i5_pool)
        elif mode == "single":
            i7, i5 = rng.choice(i7_pool), ""
        elif mode == "i7-only":
            i7, i5 = _sequence(rng, length), ""
        else:
            i7 = rng.choice(i7_pool)
            i5 = rng.choice(i5_pool) if rng.random() < 0.6 else ""
        if rng.random() < 0.05:
            i7 = ""  # a sample with no index at all
        if i7:
            sample.assign_index1(Index(name=f"i7-{k}", sequence=i7, index_type=IndexType.I7))
        if i5:
            sample.assign_index2(Index(name=f"i5-{k}", sequence=i5, index_type=IndexType.I5))
        # Sometimes a typed OverrideCycles that masks part of an index, so
        # the comparison runs over fewer cycles than the stored sequence.
        # Either index, or both: two samples with ONE stored sequence read
        # over different cycles are the case a key built from the stored
        # sequence would get wrong.
        if i7 and rng.random() < 0.20:
            def _part(cycles, length):
                read = max(1, min(length, cycles) - rng.randint(0, 2))
                mask = cycles - read
                return f"I{read}N{mask}" if mask > 0 else f"I{read}"

            part1 = _part(run.run_cycles.index1_cycles, len(i7))
            part2 = (_part(run.run_cycles.index2_cycles, len(i5))
                     if i5 and rng.random() < 0.5
                     else f"I{run.run_cycles.index2_cycles}")
            sample.override_cycles = (f"Y{run.run_cycles.read1_cycles};{part1};"
                                      f"{part2};Y{run.run_cycles.read2_cycles}")
        run.add_sample(sample)
    return run


def generated_plan_mismatches(seed, run):
    """The sheet-plan mismatch numbers for a generated run, or None.

    ``services/sheet_plan`` hands the check a {(sample id, 1 or 2): number}
    dict when the application profiles are there, and ``_effective_mismatches``
    prefers it over the sample's own number. It is the one input to the
    grouping key that is keyed by sample id rather than read off the sample,
    so about two runs in five carry one.
    """
    rng = random.Random(f"plan-{seed}")
    if rng.random() >= 0.4:
        return None
    return {(sample.id, index_num): rng.choice([0, 1, 2])
            for sample in run.samples for index_num in (1, 2)
            if rng.random() < 0.5}


# --------------------------------------------------------------------------
# The property.
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def generated():
    """Every generated run with both reports, built once for the whole file.

    The oracle is the expensive half (it compares every pair), so it runs
    once per run and the tests below share the result.
    """
    records = []
    for seed in range(ORACLE_RUNS):
        run = generated_run(seed)
        mismatches = generated_plan_mismatches(seed, run)
        groups = IndexCollisionValidator.validate_index_collision_groups(
            run, None, mismatches)
        expanded, produced = triples_from_groups(groups)
        records.append({
            "seed": seed, "run": run, "groups": groups, "mismatches": mismatches,
            "expanded": expanded, "produced": produced,
            "expected": oracle_triples(run, None, mismatches),
        })
    return records


class TestGroupedReportEqualsThePerPairScan:
    """The whole point: no collision may be lost by grouping."""

    def test_every_generated_run_reports_the_same_collisions(self, generated):
        for record in generated:
            expanded, expected = record["expanded"], record["expected"]
            assert expanded == expected, (
                f"seed {record['seed']}: grouped report and per-pair scan differ; "
                f"missing {sorted(expected - expanded)[:5]}, "
                f"extra {sorted(expanded - expected)[:5]}")
        assert len(generated) == ORACLE_RUNS

    def test_no_pair_is_named_by_two_findings(self, generated):
        """The groups of a lane partition its samples, so a colliding pair
        is expanded exactly once. Overlapping groups (groups merged by
        chaining, say) would show up here as well as above."""
        for record in generated:
            assert record["produced"] == len(record["expanded"]), (
                f"seed {record['seed']}: {record['produced']} pairs expanded but "
                f"only {len(record['expanded'])} distinct")

    def test_every_generated_run_is_refused_or_accepted_the_same(self, generated):
        """error_count > 0 agrees: no run refused today is accepted now."""
        for record in generated:
            assert bool(record["groups"]) is bool(record["expected"]), (
                f"seed {record['seed']}: one report finds a collision and the "
                f"other does not")

    def test_the_whole_check_refuses_the_same_runs(self, generated):
        """The same, through ValidationService, on a subset.

        The per-pair count the old code would have produced is exactly the
        number of oracle triples (one IndexCollision per colliding pair per
        lane), so the old error_count is reconstructible.
        """
        for record in generated[:FULL_VALIDATE_RUNS]:
            clear_validation_cache()
            result = ValidationService.validate_run(record["run"])
            # validate_run gets no profiles here, so it plans no sheet and
            # passes no mismatch dict: compare against the no-plan oracle.
            old_error_count = (result.error_count
                               - len(result.index_collision_groups)
                               + len(oracle_triples(record["run"])))
            assert result.has_errors is (old_error_count > 0), f"seed {record['seed']}"
            assert (result.error_count > 0) is (old_error_count > 0), f"seed {record['seed']}"

    def test_the_generator_plants_what_the_proof_needs(self, generated):
        """A weakened generator would make the property test vacuous.

        The thresholds are about two thirds of what the generator as written
        produces over its 600 fixed seeds, measured:

            runs that collide at all                        424
            runs with 3+ samples on one index                67
            runs colliding across two different sequences   393
            runs mixing per-sample mismatch numbers         564
            runs with a typed OverrideCycles                471
            ... of which the i5 is masked in                179
            runs using more than 4 lanes                    323
            runs with two samples on one read index         262
            runs with two i7s 1 or 2 bases apart            303
            runs with one stored index read over two
                different cycle counts                      190
            sample counts                               1..391
        """
        counts = dict.fromkeys(
            ("collide", "shared3", "cross", "mixed", "mixed_i5", "masked",
             "masked_i5", "many_lanes", "identical", "near",
             "one_stored_two_read", "plan"), 0)
        sizes = set()
        for record in generated:
            run, groups = record["run"], record["groups"]
            sizes.add(len(run.samples))
            if groups:
                counts["collide"] += 1
            # Several samples sharing one index — the case that made the
            # report explode.
            if any(not g.sample2_ids and len(g.sample1_ids) > 2 for g in groups):
                counts["shared3"] += 1
            # Two different sequences within the tolerance.
            if any(g.sample2_ids and g.sequence1 != g.sequence2 for g in groups):
                counts["cross"] += 1
            # Per-sample mismatch numbers must differ inside a run, or
            # dropping them from the grouping key would go unnoticed.
            if len({s.barcode_mismatches_index1 for s in run.samples}) > 1:
                counts["mixed"] += 1
            if len({s.barcode_mismatches_index2 for s in run.samples}) > 1:
                counts["mixed_i5"] += 1
            if record["mismatches"]:
                counts["plan"] += 1
            masked = [s for s in run.samples if s.override_cycles]
            if masked:
                counts["masked"] += 1
            if any("N" in s.override_cycles.split(";")[2] for s in masked):
                counts["masked_i5"] += 1
            if len({lane for s in run.samples for lane in s.lanes}) > 4:
                counts["many_lanes"] += 1

            indexed = [s for s in run.samples if s.has_index]
            read = [(effective_index_sequence(s, 1, run), effective_index_sequence(s, 2, run))
                    for s in indexed]
            if len(set(read)) < len(read):
                counts["identical"] += 1
            # One stored index pair read over two different cycle counts:
            # the case a grouping key built from the STORED sequence would
            # decide from one representative.
            stored: dict[tuple, set] = {}
            for sample, pair in zip(indexed, read):
                stored.setdefault((sample.index1_sequence, sample.index2_sequence),
                                  set()).add(pair)
            if any(len(pairs) > 1 for pairs in stored.values()):
                counts["one_stored_two_read"] += 1
            # Near-duplicates: two i7s one or two bases apart.
            if any(read[i] != read[j]
                   and hamming_distance(read[i][0], read[j][0]) in (1, 2)
                   for i in range(len(read)) for j in range(i + 1, len(read))):
                counts["near"] += 1

        floors = {"collide": 300, "shared3": 40, "cross": 250, "mixed": 400,
                  "mixed_i5": 400, "masked": 300, "masked_i5": 100,
                  "many_lanes": 200, "identical": 180, "near": 250,
                  "one_stored_two_read": 120, "plan": 150}
        short = {name: counts[name] for name, floor in floors.items()
                 if counts[name] < floor}
        assert not short, f"the generator plants too few of: {short} (floors {floors})"
        assert max(sizes) > 150, f"largest generated run is {max(sizes)} samples"
        assert min(sizes) == 1, f"smallest generated run is {min(sizes)} samples"


class TestTheI5ReadDirectionIsNotPartOfTheComparison:
    """The F5 plan speaks of "a pair that collides only after the i5
    direction is applied". In the code at 7c95e76 the collision check does
    NOT apply it: ``effective_index_sequence`` truncates to the cycles read
    and nothing reverse-complements an i5 (only colour analysis and the two
    sheet writers do). Pinned here both ways, so a check that started
    reverse-complementing one side of a comparison would fail:

    - two samples whose stored i5s are IDENTICAL collide, in every workflow
      (reverse-complementing one side would pull them apart);
    - two samples whose stored i5s are each other's reverse complement do
      NOT collide, in every workflow (reverse-complementing one side would
      make them identical).
    """

    I7 = "ATTACTCG"
    I5 = "TATAGCCT"
    I5_REVERSE_COMPLEMENT = "AGGCTATA"

    def _run(self, workflow, i5_of_second):
        run = SequencingRun(
            id=f"dir-{workflow}", run_name="Direction",
            instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8), i5_workflow=workflow,
            barcode_mismatches_index1=1, barcode_mismatches_index2=1)
        for n, i5 in enumerate((self.I5, i5_of_second), start=1):
            sample = Sample(id=f"d{n}", sample_id=f"D{n}", lanes=[1])
            sample.assign_index1(Index(name="i7", sequence=self.I7, index_type=IndexType.I7))
            sample.assign_index2(Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5))
            run.add_sample(sample)
        return run

    @pytest.mark.parametrize("workflow", ["", "BCLConvert", "DRAGEN"])
    def test_one_stored_i5_on_both_samples_collides_in_every_workflow(self, workflow):
        run = self._run(workflow, self.I5)
        groups = IndexCollisionValidator.validate_index_collision_groups(run)
        expanded, _ = triples_from_groups(groups)
        assert expanded == {("d1", "d2", 1)}
        assert expanded == oracle_triples(run)

    @pytest.mark.parametrize("workflow", ["", "BCLConvert", "DRAGEN"])
    def test_an_i5_against_its_reverse_complement_does_not_collide(self, workflow):
        run = self._run(workflow, self.I5_REVERSE_COMPLEMENT)
        assert reverse_complement(self.I5) == self.I5_REVERSE_COMPLEMENT
        groups = IndexCollisionValidator.validate_index_collision_groups(run)
        expanded, _ = triples_from_groups(groups)
        assert expanded == set()
        assert expanded == oracle_triples(run)

    @pytest.mark.parametrize("workflow", ["", "BCLConvert", "DRAGEN"])
    def test_the_sequence_the_check_compares_is_the_stored_one(self, workflow):
        """What a grouping key that applied the direction would break."""
        run = self._run(workflow, self.I5_REVERSE_COMPLEMENT)
        first, second = run.samples
        assert effective_index_sequence(first, 2, run) == self.I5
        assert effective_index_sequence(second, 2, run) == self.I5_REVERSE_COMPLEMENT
        keys = {IndexCollisionValidator._collision_key(s, run) for s in run.samples}
        assert len(keys) == 2
