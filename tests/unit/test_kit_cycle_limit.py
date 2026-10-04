"""A run must not ask for more cycles than its reagent kit holds.

The kit label (300) is not the limit: kits hold extra cycles, and how many
depends on the kit. The lab enters the exact number per instrument and kit
(``reagent_kit_max_cycles``); a kit without a number is not checked.
"""

import pytest

from seqsetup.data import instruments as instruments_module
from seqsetup.data.instruments import get_reagent_kit_max_cycles
from seqsetup.models.instrument_definition import (
    FlowcellDefinition,
    InstrumentDefinition,
)
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from seqsetup.services.instrument_validator import validate_instrument_yaml
from seqsetup.services.validation import ValidationService

NEXTSEQ = "NextSeq 1000/2000"
# NextSeq 1000/2000's i5 facts (spec 2026-10-04 group A2, §1).
I5_FACTS = {
    "i5_workflows": [{"name": "Standard", "i5_read_orientation": "reverse-complement"}],
    "runinfo_marks_i5_reversed": True,
}


def _instrument_yaml(**extra) -> dict:
    data = {
        "name": NEXTSEQ,
        "samplesheet_name": "NextSeq1k2k",
        "version": "1.0.0",
        "chemistry_type": "4-color",
        "flowcells": {"P3": {"lanes": 1, "reagent_kits": [50, 300]}},
        **I5_FACTS,
    }
    data.update(extra)
    return data


def _definition(limits: dict) -> InstrumentDefinition:
    return InstrumentDefinition(
        name=NEXTSEQ,
        samplesheet_name="NextSeq1k2k",
        flowcells=[FlowcellDefinition(name="P3", reagent_kits=[50, 300])],
        reagent_kit_max_cycles=limits,
        **I5_FACTS,
    )


@pytest.fixture
def synced_limit(monkeypatch):
    """NextSeq 1000/2000 synced from GitHub with 338 for the 300-cycle kit."""
    class _Repo:
        def list_all(self):
            return [_definition({300: 338})]
    monkeypatch.setattr(instruments_module, "_instrument_definition_repo", _Repo())
    monkeypatch.setattr(instruments_module, "_synced_instruments_cache", None)


@pytest.fixture
def yaml_limits(monkeypatch):
    """Use the fallback YAML; returns a setter for NextSeq's limits."""
    monkeypatch.setattr(instruments_module, "_instrument_definition_repo", None)
    monkeypatch.setattr(instruments_module, "_synced_instruments_cache", None)

    def set_limits(limits):
        config = dict(instruments_module._instruments[NEXTSEQ])
        config["reagent_kit_max_cycles"] = limits
        monkeypatch.setitem(instruments_module._instruments, NEXTSEQ, config)
    return set_limits


def _run(read1=151, read2=151, index1=10, index2=10, kit=300):
    return SequencingRun(
        run_name="Run_1",
        instrument_platform=InstrumentPlatform.NEXTSEQ_1000_2000,
        flowcell_type="P3",
        reagent_cycles=kit,
        run_cycles=RunCycles(read1, read2, index1, index2),
    )


def _cycle_errors(run):
    return [e for e in ValidationService.validate_configuration(run)
            if e.category == "cycles_exceed_kit"]


class TestInstrumentFileValidation:
    """The sync refuses a limit that cannot be right."""

    def test_valid_limits_accepted(self):
        result = validate_instrument_yaml(_instrument_yaml(reagent_kit_max_cycles={300: 338}))
        assert result.is_valid, result.errors
        assert not any(w.field == "reagent_kit_max_cycles" for w in result.warnings)

    def test_absent_is_fine(self):
        assert validate_instrument_yaml(_instrument_yaml()).is_valid

    @pytest.mark.parametrize("limits", [
        [338],                 # not a mapping
        {"300": 338},          # label not a whole number
        {0: 338},              # label not positive
        {300: "338"},          # limit not a whole number
        {300: True},           # a bool is not a number
        {300: 299},            # smaller than the label
    ])
    def test_bad_limits_refused(self, limits):
        result = validate_instrument_yaml(_instrument_yaml(reagent_kit_max_cycles=limits))
        assert not result.is_valid
        assert any(e.field.startswith("reagent_kit_max_cycles") for e in result.errors)

    def test_label_no_flowcell_offers_is_a_warning(self):
        result = validate_instrument_yaml(_instrument_yaml(reagent_kit_max_cycles={30: 60}))
        assert result.is_valid
        assert any(w.field == "reagent_kit_max_cycles" and "30" in w.message
                   for w in result.warnings)


class TestInstrumentDefinitionField:
    """The model checks the limits on every assignment and survives MongoDB."""

    def test_defaults_to_no_limits(self):
        assert InstrumentDefinition(name=NEXTSEQ, **I5_FACTS).reagent_kit_max_cycles == {}

    def test_round_trips_with_string_keys_in_storage(self):
        stored = _definition({300: 338}).to_dict()
        assert stored["reagent_kit_max_cycles"] == {"300": 338}
        assert InstrumentDefinition.from_dict(stored).reagent_kit_max_cycles == {300: 338}

    def test_from_yaml_reads_limits(self):
        inst = InstrumentDefinition.from_yaml(
            _instrument_yaml(reagent_kit_max_cycles={300: 338}), "nextseq.yaml")
        assert inst.reagent_kit_max_cycles == {300: 338}

    @pytest.mark.parametrize("limits", [{300: 299}, {300: "x"}, {"abc": 338}, {300: True}])
    def test_bad_limits_raise(self, limits):
        inst = InstrumentDefinition(name=NEXTSEQ, **I5_FACTS)
        with pytest.raises(ValueError):
            inst.reagent_kit_max_cycles = limits


class TestLookup:
    """get_reagent_kit_max_cycles reads synced and fallback YAML config."""

    def test_synced_number(self, synced_limit):
        assert get_reagent_kit_max_cycles(InstrumentPlatform.NEXTSEQ_1000_2000, 300) == 338

    def test_synced_kit_without_number(self, synced_limit):
        assert get_reagent_kit_max_cycles(InstrumentPlatform.NEXTSEQ_1000_2000, 50) is None

    def test_yaml_number(self, yaml_limits):
        yaml_limits({300: 338})
        assert get_reagent_kit_max_cycles(InstrumentPlatform.NEXTSEQ_1000_2000, 300) == 338

    def test_shipped_config_has_no_numbers(self, yaml_limits):
        assert get_reagent_kit_max_cycles(InstrumentPlatform.NEXTSEQ_1000_2000, 300) is None

    @pytest.mark.parametrize("limits", [{300: "338"}, {300: 299}, {300: True}, [338]])
    def test_malformed_yaml_number_is_ignored_and_logged(self, yaml_limits, caplog, limits):
        yaml_limits(limits)
        assert get_reagent_kit_max_cycles(InstrumentPlatform.NEXTSEQ_1000_2000, 300) is None
        assert "reagent_kit_max_cycles" in caplog.text


class TestTooManyCyclesIsAnError:
    """validate_configuration flags a total above the kit's number."""

    def test_over_the_limit_is_error(self, synced_limit):
        errs = _cycle_errors(_run(read1=160, read2=160))  # 340
        assert len(errs) == 1
        assert errs[0].severity.value == "error"
        assert errs[0].message == (
            "Too many cycles: 340. A 300-cycle kit on NextSeq 1000/2000 "
            "allows 338. Lower the cycles in Run Setup."
        )

    def test_exactly_the_limit_is_fine(self, synced_limit):
        assert _cycle_errors(_run(read1=159, read2=159)) == []  # 338

    def test_default_cycles_are_fine(self, synced_limit):
        assert _cycle_errors(_run()) == []  # 322

    def test_no_number_means_no_check(self, yaml_limits):
        assert _cycle_errors(_run(read1=301, read2=301)) == []

    def test_other_kit_without_number_not_checked(self, synced_limit):
        assert _cycle_errors(_run(read1=100, read2=100, kit=50)) == []

    def test_flagged_on_a_run_with_no_samples(self, synced_limit):
        run = _run(read1=301, read2=301)
        assert run.samples == []
        assert len(_cycle_errors(run)) == 1

    def test_run_without_cycles_not_checked(self, synced_limit):
        run = _run()
        run.run_cycles = None
        assert _cycle_errors(run) == []
