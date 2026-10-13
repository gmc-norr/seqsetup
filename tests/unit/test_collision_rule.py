"""Two dual-index samples in one lane clash only when BOTH indexes are close:
d_i7 <= 2*m_i7 AND d_i5 <= 2*m_i5 (the user's decision, 2026-10-13, on the
night run's Q1; docs/superpowers/specs/2026-10-12-collision-rule-design.md).
That is when a read can fit both samples, and it is the default of DRAGEN's
built-in BCL conversion, which the lab runs. The summed rule it replaces
raised 92 false alarms on an ordinary combinatorial plate. A pair where either
sample has no i5 keeps the i7-only rule."""

import itertools
from pathlib import Path

import pytest
import yaml

from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.index_collision_validator import IndexCollisionValidator
from seqsetup.services.validation import ValidationService
from seqsetup.services.validation_report import ValidationReportJSON

I7 = "ATTACTCG"


def _run(*pairs, m7=1, m5=1):
    """A NovaSeq X run reading 8 + 8 index cycles, one sample per (i7, i5) in lane 1."""
    run = SequencingRun(id="rule", run_name="Rule", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 8, 8),
                        barcode_mismatches_index1=m7, barcode_mismatches_index2=m5)
    for n, (i7, i5) in enumerate(pairs, start=1):
        sample = Sample(id=f"s{n}", sample_id=f"S{n:03d}", lanes=[1],
                        barcode_mismatches_index1=m7, barcode_mismatches_index2=m5)
        sample.assign_index1(Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7))
        if i5:
            sample.assign_index2(Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5))
        run.add_sample(sample)
    return run


def _collisions(run):
    return IndexCollisionValidator.validate_index_collisions(run)


class TestBothIndexesMustBeClose:
    # (i7 of sample 2, i5 of sample 2, against sample 1's ATTACTCG + TATAGCCT;
    # mismatches 1/1, so each limit is 2) -> clash?
    CASES = [
        ("ATTACTCG", "TATAGCCT", True),    # identical pair: d7 0, d5 0
        ("ATTACTCG", "TATAGCAA", True),    # d7 0, d5 2
        ("ATTACTCG", "CCTATCCT", False),   # d7 0, d5 3: the summed rule flagged it (3 <= 4)
        ("ATTACTGA", "TATAGCAA", True),    # d7 2, d5 2
        ("ATTACAGA", "TATAGCCT", False),   # d7 3, d5 0: the summed rule flagged it (3 <= 4)
        ("ATTACTCG", "ATAGAGGC", False),   # shared i7, i5 far apart: a combinatorial plate's pair
    ]

    @pytest.mark.parametrize("i7,i5,clash", CASES)
    def test_a_pair_clashes_only_when_both_are_within_the_limit(self, i7, i5, clash):
        assert bool(_collisions(_run((I7, "TATAGCCT"), (i7, i5)))) is clash

    def test_each_limit_follows_its_own_mismatch_number(self):
        # m_i7 2 (limit 4), m_i5 0 (limit 0)
        assert _collisions(_run((I7, "TATAGCCT"), ("ATTGATCC", "TATAGCCT"), m7=2, m5=0))
        assert not _collisions(_run((I7, "TATAGCCT"), ("ATTGATCC", "TATAGCCA"), m7=2, m5=0))

    def test_a_clash_carries_both_distances_and_both_limits(self):
        (c,) = _collisions(_run((I7, "TATAGCCT"), ("ATTACTGA", "TATAGCAA")))
        assert (c.index_type, c.i7_distance, c.i7_threshold, c.i5_distance, c.i5_threshold) == (
            "i7+i5", 2, 2, 2, 2)
        # The two older numbers keep their meaning: the summed distance and the
        # summed limit (a pair both close is always within the sum as well).
        assert (c.hamming_distance, c.mismatch_threshold) == (4, 4)
        assert c.collision_description.endswith("i7 distance 2 <= 2 and i5 distance 2 <= 2")


class TestASingleIndexPairKeepsTheI7Rule:
    def test_an_i7_within_the_limit_still_clashes(self):
        (c,) = _collisions(_run((I7, None), ("ATTACTGA", "TATAGCCT")))
        assert (c.index_type, c.hamming_distance, c.mismatch_threshold) == ("i7", 2, 2)
        assert c.i5_distance is None and c.i5_threshold is None
        assert c.collision_description.endswith("distance 2 <= threshold 2")

    def test_an_i7_beyond_it_does_not(self):
        assert not _collisions(_run((I7, None), ("ATTACAGA", "TATAGCCT")))


class TestACombinatorialPlate:
    """The shipped Nextera XT combinatorial kit, every i7 x i5 once: each i7
    is reused 8 times and each i5 12 times, on purpose."""

    def test_the_plate_raises_no_alarm(self):
        kit = yaml.safe_load(Path("config/indexes/nextera_xt_combinatorial.yaml").read_text())
        pairs = list(itertools.product([i["sequence"] for i in kit["i7_indexes"]],
                                       [i["sequence"] for i in kit["i5_indexes"]]))
        assert len(pairs) == 96
        assert _collisions(_run(*pairs)) == []


class TestTheReportSaysBoth:
    def test_the_json_report_carries_both_distances(self):
        import json
        run = _run((I7, "TATAGCCT"), ("ATTACTGA", "TATAGCAA"))
        result = ValidationService.validate_run(run)
        (row,) = json.loads(ValidationReportJSON.export(run, result))["errors"]["index_collisions"]
        assert {k: row[k] for k in ("hamming_distance", "mismatch_threshold", "i7_distance",
                                    "i7_threshold", "i5_distance", "i5_threshold")} == {
            "hamming_distance": 4, "mismatch_threshold": 4, "i7_distance": 2,
            "i7_threshold": 2, "i5_distance": 2, "i5_threshold": 2}


def _lane_warnings(run):
    result = ValidationService.validate_run(run)
    return [e for e in result.configuration_errors if e.category == "mismatch_threshold_risk"]


class TestTheLaneMismatchWarningIsForSingleIndexPairs:
    """The user's decision, 2026-10-13: the lane-wide "minimum i7 distance"
    warning looks at single-index pairs only. A dual-index pair is judged by
    the collision check above; samples that share an i7 on purpose are fine."""

    def test_a_shared_i7_with_far_i5s_raises_no_warning(self):
        assert _lane_warnings(_run((I7, "TATAGCCT"), (I7, "ATAGAGGC"))) == []

    def test_a_combinatorial_plate_raises_no_warning(self):
        kit = yaml.safe_load(Path("config/indexes/nextera_xt_combinatorial.yaml").read_text())
        pairs = list(itertools.product([i["sequence"] for i in kit["i7_indexes"]],
                                       [i["sequence"] for i in kit["i5_indexes"]]))
        assert _lane_warnings(_run(*pairs)) == []

    def test_a_close_single_index_pair_still_warns(self):
        (warning,) = _lane_warnings(_run((I7, None), ("ATTACTGA", None)))
        assert "minimum i7 distance (2)" in warning.message
