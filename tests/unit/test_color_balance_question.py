"""Which lanes make Mark Ready ask about color balance (F13): lanes with at
least one Error position; warnings do not count."""

from seqsetup.models.validation import (
    IndexColorBalance, LaneColorBalance, PositionColorBalance, ValidationResult,
)


def _lane(lane, *positions):
    return LaneColorBalance(lane=lane, sample_count=1,
                            i7_balance=IndexColorBalance(index_type="i7", positions=list(positions)))


OK = PositionColorBalance(position=1, c_count=1)                 # C: both channels
WARNING = PositionColorBalance(position=1, a_count=4, c_count=1)  # channel 2 at 20 %
ERROR = PositionColorBalance(position=1, a_count=1)              # A: channel 2 at 0 %


def _result(color_balance):
    return ValidationResult(duplicate_sample_ids=[], index_collisions=[], distance_matrices={},
                            color_balance=color_balance)


def test_error_position_makes_a_lane_have_errors():
    assert _lane(1, ERROR).has_errors
    assert not _lane(1, WARNING).has_errors
    assert not _lane(1, OK).has_errors


def test_i5_errors_count_too():
    lane = LaneColorBalance(lane=2, sample_count=1,
                            i5_balance=IndexColorBalance(index_type="i5", positions=[ERROR]))
    assert lane.has_errors


def test_error_lanes_are_sorted_and_skip_warning_lanes():
    result = _result({3: _lane(3, ERROR), 1: _lane(1, ERROR), 2: _lane(2, WARNING)})
    assert result.color_balance_error_lanes == [1, 3]


def test_no_color_balance_means_no_error_lanes():
    assert _result({}).color_balance_error_lanes == []


def test_four_color_instrument_has_no_error_lanes():
    from seqsetup.models.index import Index, IndexPair, IndexType
    from seqsetup.models.sample import Sample
    from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
    from seqsetup.services.validation import ValidationService, clear_validation_cache

    clear_validation_cache()
    run = SequencingRun(id="cb-4color", instrument_platform=InstrumentPlatform.HISEQ_4000,
                        run_cycles=RunCycles(151, 151, 8, 8))
    run.add_sample(Sample(sample_id="S1", index_pair=IndexPair(id="p", name="p",
        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5))))
    assert ValidationService.validate_run(run).color_balance_error_lanes == []
