"""Planning "Fill empty samples in order": samples with no index get the
next unused index of one kit, in table order, or nothing at all."""

import json

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.index_fill import COMBINATORIAL_REFUSAL, build_fill_plan

I7 = ["AAAAAAAA", "CCCCCCCC", "GGGGGGGG", "TTTTTTTT", "ACACACAC"]
I5 = ["AGAGAGAG", "CTCTCTCT", "GAGAGAGA", "TCTCTCTC", "CACACACA"]


def _pair(k, i7=None, i5=None):
    return IndexPair(
        id=f"p{k}", name=f"UDP{k:04d}",
        index1=Index(name=f"i7-{k}", sequence=i7 or I7[k], index_type=IndexType.I7),
        index2=Index(name=f"i5-{k}", sequence=i5 or I5[k], index_type=IndexType.I5),
    )


def _dual_kit(n=5, pairs=None):
    return IndexKit(name="Kit", version="1", index_mode=IndexMode.UNIQUE_DUAL,
                    index_pairs=pairs if pairs is not None else [_pair(k) for k in range(n)])


def _single_kit(n=4):
    return IndexKit(name="Single", version="1", index_mode=IndexMode.SINGLE,
                    i7_indexes=[Index(name=f"S{k}", sequence=I7[k], index_type=IndexType.I7)
                                for k in range(n)])


def _run(n_samples=3):
    run = SequencingRun(run_name="R", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 8, 8))
    for k in range(1, n_samples + 1):
        run.add_sample(Sample(id=f"s{k}", sample_id=f"S{k}", lanes=[1]))
    return run


def _mapping(plan):
    return [(r.sample_label, r.entry.name) for r in plan.rows]


class TestFillOrder:
    """Samples in table order get the kit's indexes in kit order."""

    def test_fills_every_empty_sample_from_the_first_index(self):
        plan = build_fill_plan(_run(), _dual_kit())
        assert plan.can_apply and plan.problem == ""
        assert _mapping(plan) == [("S1", "UDP0000"), ("S2", "UDP0001"), ("S3", "UDP0002")]
        assert plan.start.name == "UDP0000" and plan.skipped == []

    def test_start_picks_where_to_begin(self):
        plan = build_fill_plan(_run(2), _dual_kit(), start_id="p2")
        assert _mapping(plan) == [("S1", "UDP0002"), ("S2", "UDP0003")]

    def test_never_wraps_to_the_beginning(self):
        plan = build_fill_plan(_run(2), _dual_kit(), start_id="p4")
        assert not plan.can_apply and plan.rows == []
        assert plan.problem == ("Not enough unused indexes: 2 needed, 1 left in Kit from "
                                "UDP0004. Pick an earlier start or another kit.")

    def test_unknown_start_raises(self):
        with pytest.raises(ValueError):
            build_fill_plan(_run(), _dual_kit(), start_id="nope")


class TestOnlyEmptySamples:
    """A sample with any index is never a target and is never changed."""

    def test_indexed_and_partial_samples_are_left_alone(self):
        run = _run(4)
        run.samples[1].assign_index(_pair(4))                       # S2: full pair
        run.samples[2].assign_index2(Index(name="x", sequence="GTGTGTGT",
                                           index_type=IndexType.I5))  # S3: i5 only
        plan = build_fill_plan(run, _dual_kit())
        assert [r.sample_label for r in plan.rows] == ["S1", "S4"]
        assert plan.needed == 2

    def test_nothing_to_do(self):
        run = _run(1)
        run.samples[0].assign_index(_pair(0))
        plan = build_fill_plan(run, _dual_kit())
        assert plan.problem == "Every sample already has an index." and not plan.can_apply


class TestPartialI5OnlySamples:
    """A sample with only an i5 index is never a fill target, but the plan
    says so instead of implying every sample already has an index."""

    def test_i5_only_sample_blocks_apply_and_is_named(self):
        run = _run(2)
        run.samples[0].assign_index2(Index(name="x", sequence="GTGTGTGT",
                                           index_type=IndexType.I5))  # S1: i5 only
        run.samples[1].assign_index(_pair(4))                        # S2: full pair
        plan = build_fill_plan(run, _dual_kit())
        assert plan.partial == ["S1"]
        assert not plan.can_apply
        assert plan.problem == (
            "Fill in order only fills samples with no index at all. 1 sample(s) "
            "have only an i5 index; give them an i7 by hand: S1."
        )

    def test_i5_only_sample_is_skipped_but_others_still_fill(self):
        run = _run(3)
        run.samples[1].assign_index2(Index(name="x", sequence="GTGTGTGT",
                                           index_type=IndexType.I5))  # S2: i5 only
        plan = build_fill_plan(run, _dual_kit())
        assert [r.sample_label for r in plan.rows] == ["S1", "S3"]
        assert plan.partial == ["S2"]
        assert plan.problem == ""

    def test_many_partial_samples_are_summarized_after_ten(self):
        run = _run(0)
        for k in range(1, 13):
            sample = Sample(id=f"p{k}", sample_id=f"P{k:02d}", lanes=[1])
            sample.assign_index2(Index(name="x", sequence="GTGTGTGT", index_type=IndexType.I5))
            run.add_sample(sample)
        plan = build_fill_plan(run, _dual_kit())
        assert plan.problem == (
            "Fill in order only fills samples with no index at all. 12 sample(s) "
            "have only an i5 index; give them an i7 by hand: P01, P02, P03, P04, "
            "P05, P06, P07, P08, P09, P10, and 2 more."
        )

    def test_fully_indexed_run_keeps_the_original_message(self):
        run = _run(1)
        run.samples[0].assign_index(_pair(0))
        plan = build_fill_plan(run, _dual_kit())
        assert plan.problem == "Every sample already has an index." and plan.partial == []


class TestSkipUsed:
    """An index whose i7 or i5 is already used in the run is skipped."""

    def test_default_start_is_first_unused(self):
        run = _run(3)
        run.samples[0].assign_index(_pair(0))
        plan = build_fill_plan(run, _dual_kit())
        assert plan.start.name == "UDP0001"
        assert _mapping(plan) == [("S2", "UDP0001"), ("S3", "UDP0002")]

    def test_used_index_after_the_start_is_skipped_and_named(self):
        run = _run(3)
        run.samples[0].assign_index(_pair(1))
        plan = build_fill_plan(run, _dual_kit(), start_id="p0")
        assert _mapping(plan) == [("S2", "UDP0000"), ("S3", "UDP0002")]
        assert plan.skipped == ["UDP0001"]

    def test_shared_i5_alone_counts_as_used(self):
        run = _run(2)
        other = _pair(4, i5=I5[0])            # another kit's pair sharing UDP0000's i5
        run.samples[0].assign_index(other)
        plan = build_fill_plan(run, _dual_kit(4))
        assert _mapping(plan) == [("S2", "UDP0001")]

    def test_a_kit_repeating_a_sequence_cannot_give_it_twice(self):
        pairs = [_pair(0), _pair(1, i7=I7[0]), _pair(2)]   # p1 repeats p0's i7
        plan = build_fill_plan(_run(2), _dual_kit(pairs=pairs))
        assert _mapping(plan) == [("S1", "UDP0000"), ("S2", "UDP0002")]
        assert plan.skipped == ["UDP0001"]

    def test_all_used(self):
        run = _run(3)
        run.samples[0].assign_index(_pair(0))
        plan = build_fill_plan(run, _dual_kit(1))
        assert plan.problem == "Every index in Kit is already used in this run."


class TestKitModes:

    def test_single_kit_fills_i7(self):
        plan = build_fill_plan(_run(2), _single_kit())
        assert plan.mode == "i7"
        assert [r.entry.id for r in plan.rows] == ["Single_i7_S0", "Single_i7_S1"]
        assert all(r.entry.i5 is None for r in plan.rows)

    def test_combinatorial_kit_refused(self):
        kit = IndexKit(name="Combo", version="1", index_mode=IndexMode.COMBINATORIAL,
                       i7_indexes=[Index(name="a", sequence=I7[0], index_type=IndexType.I7)],
                       i5_indexes=[Index(name="b", sequence=I5[0], index_type=IndexType.I5)])
        plan = build_fill_plan(_run(), kit)
        assert plan.problem == COMBINATORIAL_REFUSAL and not plan.can_apply

    def test_empty_kit(self):
        plan = build_fill_plan(_run(), _dual_kit(0))
        assert plan.problem == "Kit has no indexes."


class TestSignature:

    def test_signature_is_what_will_be_saved(self):
        plan = build_fill_plan(_run(2), _dual_kit())
        assert json.loads(plan.signature()) == [
            "Kit:1",
            [["s1", "p0", I7[0], I5[0]], ["s2", "p1", I7[1], I5[1]]],
        ]

    def test_signature_changes_when_only_a_kit_sequence_changes(self):
        """A kit re-synced with a changed sequence but the same name, version
        and index ids must not pass as the kit the preview showed."""
        run = _run(2)
        before = build_fill_plan(run, _dual_kit()).signature()
        edited = _dual_kit(pairs=[_pair(0, i7="GTGTGTGT")] + [_pair(k) for k in range(1, 5)])
        assert build_fill_plan(run, edited).signature() != before

    def test_signature_changes_when_the_run_changes(self):
        run = _run(2)
        before = build_fill_plan(run, _dual_kit(), start_id="p0").signature()
        run.add_sample(Sample(id="s3", sample_id="S3", lanes=[1]))
        assert build_fill_plan(run, _dual_kit(), start_id="p0").signature() != before


def test_planning_changes_nothing():
    run = _run(3)
    before = run.to_dict()
    build_fill_plan(run, _dual_kit())
    assert run.to_dict() == before
