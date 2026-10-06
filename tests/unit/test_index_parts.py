"""An index part of OverrideCycles starts with the index and holds one run of
index cycles, in both index parts (spec 2026-10-05 group A3, §4). The checks
compare stored indexes from the first cycle of the read, so a mask they
cannot compare is refused rather than compared wrongly."""

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.cycle_calculator import (
    INDEX1_ORDER_RULE,
    INDEX2_ORDER_RULE,
    INDEX_SPLIT_RULE,
    CycleCalculator,
)
from seqsetup.services.validation import ValidationService

RC = RunCycles(151, 151, 10, 10)


class TestTheRules:
    """The two rule texts."""

    def test_the_index_1_order_rule(self):
        assert INDEX1_ORDER_RULE == (
            "Index 1 in OverrideCycles starts with the index in SeqSetup: the index first, "
            "then any masked or UMI cycles (for example I8N2 or I8U9). SeqSetup's checks "
            "compare the index from the first cycle of its read."
        )

    def test_the_split_rule(self):
        assert INDEX_SPLIT_RULE == (
            "An index part of OverrideCycles holds one run of index cycles in SeqSetup (for "
            "example I8N2, not I4N2I4). SeqSetup's checks compare the index as one run of "
            "cycles."
        )


class TestTheIndex1Part:
    """Nothing comes before the index in the Index 1 part."""

    @pytest.mark.parametrize("value", [
        "Y151;N2I8;I8N2;Y151", "Y151;U2I8;I8N2;Y151", "Y151;N1I8N1;I10;Y151",
        "y151;n2i8;i10;y151", "Y151,N2I8,I10,Y151", "Y151;Y2I8;I8N2;Y151", "y151;y2i8;i10;y151",
    ])
    def test_cycles_before_the_index_are_refused(self, value):
        assert CycleCalculator.override_cycles_problem(value, RC) == "index1_order"

    @pytest.mark.parametrize("value", [
        "Y151;I8N2;I8N2;Y151", "Y151;I10;I10;Y151", "Y151;I8U2;I8N2;Y151", "Y151;N10;I10;Y151",
    ])
    def test_the_index_first_or_no_index_is_fine(self, value):
        assert CycleCalculator.override_cycles_problem(value, RC) is None

    def test_a_single_index_run(self):
        rc = RunCycles(151, 151, 10, 0)
        assert CycleCalculator.override_cycles_problem("Y151;N2I8;Y151", rc) == "index1_order"
        assert CycleCalculator.override_cycles_problem("Y151;I8N2;Y151", rc) is None

    def test_the_index_1_part_is_checked_before_the_index_2_part(self):
        assert CycleCalculator.override_cycles_problem("Y151;N2I8;N2I8;Y151", RC) == "index1_order"

    def test_a_mismatch_is_reported_first(self):
        assert CycleCalculator.override_cycles_problem("Y151;N2I8;I8N2", RC) == "mismatch"


class TestAYBeforeTheIndex:
    """A Y before the index is refused in either index part, like an N or U:
    the checks would compare the index from the wrong cycle (the plan
    review's case, spec §4)."""

    @pytest.mark.parametrize("value", ["Y151;I8N2;Y2I8;Y151", "Y151;I10;Y1I8N1;Y151"])
    def test_in_the_index_2_part(self, value):
        assert CycleCalculator.override_cycles_problem(value, RC) == "index2_order"

    def test_in_a_single_index_run(self):
        rc = RunCycles(151, 151, 6, 0)
        assert CycleCalculator.override_cycles_problem("Y151;Y2I4;Y151", rc) == "index1_order"

    @pytest.mark.parametrize("value", ["Y151;I10;Y10;Y151", "Y151;I8Y2;I10;Y151"])
    def test_a_y_part_with_no_index_or_after_it_is_not_this_rule(self, value):
        assert CycleCalculator.override_cycles_problem(value, RC) is None


class TestOneRunOfIndexCycles:
    """An index part holds one I segment, in either index part."""

    @pytest.mark.parametrize("value", [
        "Y151;I4N2I4;I10;Y151", "Y151;I10;I4N2I4;Y151", "Y151;I4I6;I10;Y151",
        "Y151;I10;I5I5;Y151",
    ])
    def test_two_runs_are_refused(self, value):
        assert CycleCalculator.override_cycles_problem(value, RC) == "index_split"

    def test_cycles_masked_before_the_index_are_reported_first(self):
        assert CycleCalculator.override_cycles_problem("Y151;N2I4I4;I10;Y151", RC) == "index1_order"
        assert CycleCalculator.override_cycles_problem("Y151;I10;N2I4I4;Y151", RC) == "index2_order"

    def test_umi_in_the_index_read_is_fine(self):
        # Illumina's UMI examples: I8U9 in Index 1, U10 in Index 2.
        rc = RunCycles(151, 151, 17, 10)
        assert CycleCalculator.override_cycles_problem("Y151;I8U9;U10;Y151", rc) is None


def _sample(sample_id: str, override: str) -> Sample:
    return Sample(sample_id=sample_id, lanes=[1], override_cycles=override, index_pair=IndexPair(
        id=f"p-{sample_id}", name=f"p-{sample_id}",
        index1=Index(name=f"{sample_id}-i7", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name=f"{sample_id}-i5", sequence="TATAGCCT", index_type=IndexType.I5),
    ))


def _errors(category: str, *samples: Sample) -> list:
    run = SequencingRun(instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
                        run_cycles=RC, samples=list(samples))
    return [e for e in ValidationService.validate_configuration(run) if e.category == category]


class TestMarkReadyRefusesThem:
    """Mark Ready names the samples and gives the rule."""

    def test_the_index_1_order_message(self):
        (error,) = _errors("override_cycles_index1_order", _sample("S1", "Y151;N2I8;I8N2;Y151"))
        assert error.message == (
            "1 sample(s) have an OverrideCycles whose Index 1 part has cycles before the "
            f"index: S1. {INDEX1_ORDER_RULE}"
        )
        assert error.sample_names == ["S1"]
        assert error.severity.value == "error"

    def test_the_index_2_order_message(self):
        # A2's message, worded for a Y too (spec §4, Messages).
        (error,) = _errors("override_cycles_index2_order", _sample("S1", "Y151;I8N2;Y2I8;Y151"))
        assert error.message == (
            "1 sample(s) have an OverrideCycles whose Index 2 part has cycles before the "
            f"index: S1. {INDEX2_ORDER_RULE}"
        )

    def test_the_plan_reviews_lane(self):
        # I4N2 beside Y2I4 on a 6-cycle Index 1 read: BCL Convert would read
        # the two i7s from different cycles, so Mark Ready refuses the second.
        def single(sample_id, sequence, override):
            sample = Sample(sample_id=sample_id, lanes=[1], override_cycles=override,
                            barcode_mismatches_index1=0)
            sample.assign_index1(Index(name=f"{sample_id}-i7", sequence=sequence,
                                       index_type=IndexType.I7))
            return sample
        run = SequencingRun(instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
                            run_cycles=RunCycles(151, 151, 6, 0),
                            samples=[single("A", "ACGT", "Y151;I4N2;Y151"),
                                     single("B", "GTAC", "Y151;Y2I4;Y151")])
        errors = [e for e in ValidationService.validate_configuration(run)
                  if e.category == "override_cycles_index1_order"]
        assert [e.sample_names for e in errors] == [["B"]]

    def test_the_split_message(self):
        (error,) = _errors("override_cycles_index_split", _sample("S1", "Y151;I8N2;I4N2I4;Y151"),
                           _sample("S2", "Y151;I4N2I4;I8N2;Y151"))
        assert error.message == (
            "2 sample(s) have an OverrideCycles with an index part of more than one run of "
            f"index cycles: S1, S2. {INDEX_SPLIT_RULE}"
        )
        assert error.sample_names == ["S1", "S2"]

    def test_a_good_value_gives_neither(self):
        sample = _sample("S1", "Y151;I8N2;I8N2;Y151")
        assert _errors("override_cycles_index1_order", sample) == []
        assert _errors("override_cycles_index_split", sample) == []
