"""The colour balance and dark-cycle checks run on the instrument's own
channels, never on made-up ones.

``_calculate_index_color_balance`` falls back to XLEAP Blue/Green when it is
given no channel configuration, and ``get_channel_config`` gives none for an
instrument that is not 2-color or states no ``channel1_bases``. A run on such
an instrument with ``color_balance_enabled`` on was checked against those
invented channels and its lanes marked balanced or not on that basis (review
CONFIG-3). The instrument rulebook now refuses such a file; a stored
instrument record could still say it, so the check itself refuses to run and
says why.
"""

import pytest

from seqsetup.data import instruments as instruments_module
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.validation import ValidationService, clear_validation_cache

FOUR_COLOR = InstrumentPlatform.HISEQ_4000


@pytest.fixture
def balance_on_a_4_color_instrument(monkeypatch):
    """The local file's HiSeq 4000 with colour balance switched on: a 4-color
    instrument states no channels, so there are none to count."""
    monkeypatch.setattr(instruments_module, "_instrument_definition_repo", None)
    monkeypatch.setattr(instruments_module, "_synced_instruments_cache", None)
    config = dict(instruments_module._instruments[FOUR_COLOR.value])
    config["color_balance_enabled"] = True
    monkeypatch.setitem(instruments_module._instruments, FOUR_COLOR.value, config)
    clear_validation_cache()


def _run() -> SequencingRun:
    run = SequencingRun(id="cb-no-channels", run_name="CB-NO-CHANNELS",
                        instrument_platform=FOUR_COLOR, flowcell_type="Standard",
                        reagent_cycles=300, run_cycles=RunCycles(151, 151, 8, 8))
    for sample_id, i7, i5 in (("S1", "GGACTCCT", "TATAGCCT"),
                              ("S2", "TAAGGCGA", "ATAGAGGC")):
        run.add_sample(Sample(sample_id=sample_id, lanes=list(range(1, 9)), index_pair=IndexPair(
            id=f"p-{sample_id}", name=sample_id,
            index1=Index(name=f"{sample_id}-i7", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"{sample_id}-i5", sequence=i5, index_type=IndexType.I5))))
    return run


class TestAnInstrumentThatStatesNoChannels:

    def test_no_lane_is_judged_on_made_up_channels(self, balance_on_a_4_color_instrument):
        result = ValidationService.validate_run(_run())

        assert result.color_balance == {}
        assert result.color_balance_error_lanes == []
        assert result.dark_cycle_errors == []

    def test_the_run_says_why_the_check_did_not_run(self, balance_on_a_4_color_instrument):
        result = ValidationService.validate_run(_run())

        said = [e for e in result.configuration_errors
                if e.category == "color_balance_without_channels"]
        assert len(said) == 1, [e.category for e in result.configuration_errors]
        assert FOUR_COLOR.value in said[0].message

    def test_the_run_has_no_other_error_to_hide_behind(self, balance_on_a_4_color_instrument):
        """So Mark Ready refuses it for this reason and no other."""
        result = ValidationService.validate_run(_run())

        assert [e.category for e in result.configuration_errors] == [
            "color_balance_without_channels"]
        assert result.error_count == 1


class TestAnInstrumentThatStatesItsChannels:

    def test_a_2_color_run_is_still_checked(self):
        clear_validation_cache()
        run = _run()
        run.instrument_platform = InstrumentPlatform.NOVASEQ_X
        run.flowcell_type = "10B"
        result = ValidationService.validate_run(run)

        assert result.color_balance != {}
        assert [e.category for e in result.configuration_errors
                if e.category == "color_balance_without_channels"] == []
