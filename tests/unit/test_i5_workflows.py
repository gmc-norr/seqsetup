"""The two i5 facts an instrument gives: how it reads the i5 in each of its
workflows, and whether its RunInfo.xml marks a reversed i5 read (spec
2026-10-04 group A2, §1). The validator and the model check them the same
way, so a record a sync stores always loads again."""

import dataclasses
from pathlib import Path

import pytest
import yaml

from seqsetup.data.instruments import InstrumentConfigError, load_checked_instrument_file
from seqsetup.models.instrument_definition import (
    I5Workflow,
    InstrumentDefinition,
    InstrumentRecordError,
)
from seqsetup.services.instrument_validator import validate_instrument_yaml

CONFIG = Path(__file__).resolve().parents[2] / "config"
FORWARD = "forward"
REVERSED = "reverse-complement"
REMOVE = object()
I5_FIELDS = ("i5_workflows", "runinfo_marks_i5_reversed",
             "i5_read_orientation", "samplesheet_v2_i5_orientation")


def _workflow(name: str, orientation: str) -> dict:
    return {"name": name, "i5_read_orientation": orientation}


def _yaml(**changes) -> dict:
    """A valid single-instrument file, with some fields changed (REMOVE drops one)."""
    data = {
        "name": "MiSeq i100 Series",
        "samplesheet_name": "MiSeqi100Series",
        "version": "1.0.0",
        "chemistry_type": "4-color",
        "flowcells": {"5M": {"lanes": 1, "reads": 5000000, "reagent_kits": [100]}},
        "i5_workflows": [_workflow("Index-first", FORWARD), _workflow("Read-first", REVERSED)],
        "runinfo_marks_i5_reversed": True,
    }
    for key, value in changes.items():
        if value is REMOVE:
            data.pop(key, None)
        else:
            data[key] = value
    return data


def _stored(**changes) -> dict:
    """A stored record (to_dict of a valid one), with some fields changed."""
    data = InstrumentDefinition.from_yaml(_yaml(), "i100.yaml").to_dict()
    for key, value in changes.items():
        if value is REMOVE:
            data.pop(key, None)
        else:
            data[key] = value
    return data


BAD = [
    pytest.param({"i5_workflows": REMOVE}, "i5_workflows", id="no-workflows"),
    pytest.param({"i5_workflows": []}, "i5_workflows", id="empty-list"),
    pytest.param({"i5_workflows": "Index-first"}, "i5_workflows", id="text"),
    pytest.param({"i5_workflows": None}, "i5_workflows", id="null"),
    pytest.param({"i5_workflows": [{"name": "A"}]}, "i5_workflows", id="no-orientation"),
    pytest.param({"i5_workflows": [{**_workflow("A", FORWARD), "lanes": 1}]}, "i5_workflows",
                 id="extra-key"),
    pytest.param({"i5_workflows": ["Index-first"]}, "i5_workflows", id="entry-not-a-mapping"),
    pytest.param({"i5_workflows": [_workflow("", FORWARD)]}, "i5_workflows", id="empty-name"),
    pytest.param({"i5_workflows": [_workflow(" A", FORWARD)]}, "i5_workflows", id="leading-space"),
    pytest.param({"i5_workflows": [_workflow("A" * 65, FORWARD)]}, "i5_workflows",
                 id="65-characters"),
    pytest.param({"i5_workflows": [_workflow("A/B", FORWARD)]}, "i5_workflows", id="slash"),
    pytest.param({"i5_workflows": [_workflow("A\nB", FORWARD)]}, "i5_workflows", id="line-break"),
    pytest.param({"i5_workflows": [_workflow(7, FORWARD)]}, "i5_workflows", id="number-name"),
    pytest.param({"i5_workflows": [_workflow("A", "forwards")]}, "i5_workflows",
                 id="bad-orientation"),
    pytest.param({"i5_workflows": [_workflow("A", [FORWARD])]}, "i5_workflows",
                 id="orientation-list"),
    pytest.param({"i5_workflows": [_workflow("Standard", FORWARD), _workflow("standard", REVERSED)]},
                 "i5_workflows", id="same-name-ignoring-case"),
    pytest.param({"runinfo_marks_i5_reversed": REMOVE}, "runinfo_marks_i5_reversed",
                 id="no-runinfo"),
    pytest.param({"runinfo_marks_i5_reversed": "true"}, "runinfo_marks_i5_reversed",
                 id="runinfo-text"),
    pytest.param({"runinfo_marks_i5_reversed": 1}, "runinfo_marks_i5_reversed",
                 id="runinfo-number"),
    pytest.param({"runinfo_marks_i5_reversed": None}, "runinfo_marks_i5_reversed",
                 id="runinfo-null"),
    pytest.param({"i5_read_orientation": FORWARD}, "i5_read_orientation", id="old-read-key"),
    pytest.param({"samplesheet_v2_i5_orientation": FORWARD}, "samplesheet_v2_i5_orientation",
                 id="old-sheet-key"),
]


class TestTheRules:
    """Each rule is refused by the validator, by the model from a file, by the
    model from a stored record, and in the local file, with the same text."""

    @pytest.mark.parametrize("changes,field", BAD)
    def test_the_validator_refuses_it(self, changes, field):
        result = validate_instrument_yaml(_yaml(**changes), "i100.yaml")
        assert not result.is_valid
        assert [e.field for e in result.errors] == [field]

    @pytest.mark.parametrize("changes,field", BAD)
    def test_a_file_is_refused_by_the_model_with_the_validators_text(self, changes, field):
        errors = validate_instrument_yaml(_yaml(**changes), "i100.yaml").errors
        with pytest.raises(InstrumentRecordError) as exc:
            InstrumentDefinition.from_yaml(_yaml(**changes), "i100.yaml")
        assert str(exc.value) == "MiSeq i100 Series: " + "; ".join(str(e) for e in errors)

    @pytest.mark.parametrize("changes,field", BAD)
    def test_a_stored_record_is_refused_with_the_validators_text(self, changes, field):
        errors = validate_instrument_yaml(_yaml(**changes), "i100.yaml").errors
        with pytest.raises(InstrumentRecordError) as exc:
            InstrumentDefinition.from_dict(_stored(**changes))
        assert str(exc.value) == "MiSeq i100 Series: " + "; ".join(str(e) for e in errors)

    @pytest.mark.parametrize("changes,field", BAD)
    def test_the_local_file_stops_the_start(self, tmp_path, changes, field):
        data = yaml.safe_load((CONFIG / "instruments.yaml").read_text())
        entry = {k: v for k, v in _yaml(**changes).items() if k != "name"}
        data["instruments"]["MiSeq i100 Series"] = entry
        path = tmp_path / "instruments.yaml"
        path.write_text(yaml.safe_dump(data))
        with pytest.raises(InstrumentConfigError) as exc:
            load_checked_instrument_file(path)
        assert f"MiSeq i100 Series: {field}: " in str(exc.value)

    def test_the_old_keys_point_to_the_new_ones(self):
        result = validate_instrument_yaml(_yaml(i5_read_orientation=FORWARD), "i100.yaml")
        assert str(result.errors[0]) == (
            "i5_read_orientation: Replaced by i5_workflows and runinfo_marks_i5_reversed; "
            "see Instruments in the admin guide"
        )

    def test_a_record_error_is_a_value_error(self):
        assert issubclass(InstrumentRecordError, ValueError)


class TestGoodValues:
    """What the rules allow."""

    @pytest.mark.parametrize("name", [
        "Index-first", "v1.5 reagents", "Standard_kits", "A", "A" * 64, "7 lanes",
    ])
    def test_a_name_that_is_allowed(self, name):
        changes = {"i5_workflows": [_workflow(name, FORWARD)]}
        assert validate_instrument_yaml(_yaml(**changes), "i100.yaml").is_valid
        inst = InstrumentDefinition.from_yaml(_yaml(**changes), "i100.yaml")
        assert inst.i5_workflows == (I5Workflow(name, FORWARD),)

    def test_runinfo_false_is_allowed(self):
        inst = InstrumentDefinition.from_yaml(_yaml(runinfo_marks_i5_reversed=False), "i100.yaml")
        assert inst.runinfo_marks_i5_reversed is False

    def test_the_order_is_kept(self):
        inst = InstrumentDefinition.from_yaml(_yaml(), "i100.yaml")
        assert inst.i5_workflows == (
            I5Workflow("Index-first", FORWARD), I5Workflow("Read-first", REVERSED),
        )

    def test_a_stored_record_loads_again(self):
        inst = InstrumentDefinition.from_yaml(_yaml(), "i100.yaml")
        again = InstrumentDefinition.from_dict(inst.to_dict())
        assert again.i5_workflows == inst.i5_workflows
        assert again.runinfo_marks_i5_reversed is True

    def test_the_stored_form_is_plain_data(self):
        stored = InstrumentDefinition.from_yaml(_yaml(), "i100.yaml").to_dict()
        assert stored["i5_workflows"] == [
            _workflow("Index-first", FORWARD), _workflow("Read-first", REVERSED),
        ]
        assert stored["runinfo_marks_i5_reversed"] is True
        assert "i5_read_orientation" not in stored
        assert "samplesheet_v2_i5_orientation" not in stored


class TestTheModel:
    """The model checks the facts on every assignment and has no defaults."""

    def _inst(self) -> InstrumentDefinition:
        return InstrumentDefinition.from_yaml(_yaml(), "i100.yaml")

    def test_neither_fact_has_a_default(self):
        with pytest.raises(TypeError):
            InstrumentDefinition(name="MiSeq")
        with pytest.raises(TypeError):
            InstrumentDefinition(name="MiSeq", runinfo_marks_i5_reversed=False)
        with pytest.raises(TypeError):
            InstrumentDefinition(name="MiSeq", i5_workflows=[_workflow("Standard", FORWARD)])

    def test_mappings_become_frozen_workflows(self):
        inst = InstrumentDefinition(
            name="MiSeq", i5_workflows=[_workflow("Standard", FORWARD)],
            runinfo_marks_i5_reversed=False,
        )
        assert inst.i5_workflows == (I5Workflow("Standard", FORWARD),)
        with pytest.raises(dataclasses.FrozenInstanceError):
            inst.i5_workflows[0].name = "Other"

    @pytest.mark.parametrize("value", [
        [], "Standard", [_workflow("A", "forwards")], [_workflow("A", FORWARD), _workflow("a", FORWARD)],
    ])
    def test_assigning_bad_workflows_is_refused(self, value):
        inst = self._inst()
        with pytest.raises(ValueError, match="i5_workflows"):
            inst.i5_workflows = value
        assert len(inst.i5_workflows) == 2

    @pytest.mark.parametrize("value", ["true", 1, None])
    def test_assigning_a_bad_runinfo_value_is_refused(self, value):
        inst = self._inst()
        with pytest.raises(ValueError, match="runinfo_marks_i5_reversed"):
            inst.runinfo_marks_i5_reversed = value
        assert inst.runinfo_marks_i5_reversed is True

    def test_a_workflow_checks_itself(self):
        with pytest.raises(ValueError):
            I5Workflow("A", "forwards")
        with pytest.raises(ValueError):
            I5Workflow("", FORWARD)

    @pytest.mark.parametrize("changes", [
        pytest.param({"flowcells": ["5M"]}, id="flowcell-not-a-mapping"),
        pytest.param({"onboard_applications": "BCLConvert"}, id="apps-text"),
        pytest.param({"chemistry_type": "5-color"}, id="bad-chemistry"),
        pytest.param({"reagent_kit_max_cycles": {"300": "lots"}}, id="bad-kit-limit"),
    ])
    def test_a_stored_record_of_the_wrong_shape_names_the_record(self, changes):
        with pytest.raises(InstrumentRecordError, match=r"^MiSeq i100 Series: "):
            InstrumentDefinition.from_dict(_stored(**changes))

    def test_a_record_without_a_name_is_still_named(self):
        with pytest.raises(InstrumentRecordError, match=r"^an instrument record: "):
            InstrumentDefinition.from_dict(_stored(name=REMOVE, i5_workflows=REMOVE))


BUILT_IN = {
    "MiSeq i100 Series": ([("Index-first", FORWARD), ("Read-first", REVERSED)], True),
    "MiniSeq": ([("Standard kits", REVERSED), ("Rapid kits", FORWARD)], False),
    "NovaSeq 6000": ([("v1.5 reagents", REVERSED), ("v1.0 reagents", FORWARD)], False),
    "NextSeq 500/550": ([("Standard", REVERSED)], False),
    "HiSeq 4000": ([("Standard", REVERSED)], False),
    "HiSeq X": ([("Standard", REVERSED)], False),
    "NextSeq 1000/2000": ([("Standard", REVERSED)], True),
    "NovaSeq X Series": ([("Standard", REVERSED)], True),
    "MiSeq": ([("Standard", FORWARD)], False),
    "HiSeq 2000/2500": ([("Standard", FORWARD)], False),
    "GAIIx": ([("Standard", FORWARD)], False),
}


def _example_files() -> dict:
    files = {}
    for path in sorted((CONFIG / "instruments").glob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        files[data["name"]] = (path.name, data)
    return files


class TestBuiltInInstruments:
    """The shipped local file and example files give the facts of the spec's
    table, pass the checks, and load again once stored."""

    def test_every_instrument_is_listed(self):
        local = yaml.safe_load((CONFIG / "instruments.yaml").read_text())["instruments"]
        assert set(local) == set(BUILT_IN)
        assert set(_example_files()) == set(BUILT_IN)

    @pytest.mark.parametrize("name", sorted(BUILT_IN))
    def test_the_local_file_gives_the_tables_facts(self, name):
        entry = yaml.safe_load((CONFIG / "instruments.yaml").read_text())["instruments"][name]
        workflows, marks = BUILT_IN[name]
        assert entry["i5_workflows"] == [_workflow(n, o) for n, o in workflows]
        assert entry["runinfo_marks_i5_reversed"] is marks

    @pytest.mark.parametrize("name", sorted(BUILT_IN))
    def test_the_example_file_gives_the_tables_facts_and_loads_again(self, name):
        filename, data = _example_files()[name]
        result = validate_instrument_yaml(data, filename)
        assert result.errors == []
        inst = InstrumentDefinition.from_yaml(data, filename)
        workflows, marks = BUILT_IN[name]
        assert inst.i5_workflows == tuple(I5Workflow(n, o) for n, o in workflows)
        assert inst.runinfo_marks_i5_reversed is marks
        again = InstrumentDefinition.from_dict(inst.to_dict())
        assert again.i5_workflows == inst.i5_workflows
        assert again.runinfo_marks_i5_reversed is marks

    def test_the_local_file_passes(self):
        load_checked_instrument_file(CONFIG / "instruments.yaml")


class TestTheLookupsCarryTheFacts:
    """A synced record reaches the lookups with the two facts, in the shape a
    local entry gives them, and without the old keys (spec §2)."""

    def teardown_method(self):
        from seqsetup.data import instruments as instruments_module
        instruments_module.set_instrument_definition_repo(None)
        instruments_module.clear_synced_instruments_cache()

    def _sync(self, inst):
        from seqsetup.data import instruments as instruments_module

        class _Repo:
            def list_all(self_inner):
                return [inst]

        instruments_module.set_instrument_definition_repo(_Repo())

    def test_the_config_and_the_list_carry_the_facts(self):
        from seqsetup.data.instruments import get_all_instruments, get_instrument_config
        self._sync(InstrumentDefinition.from_yaml(_yaml(), "i100.yaml"))
        config = get_instrument_config("MiSeq i100 Series")
        (listed,) = get_all_instruments()
        local = yaml.safe_load((CONFIG / "instruments.yaml").read_text())["instruments"]
        for entry in (config, listed):
            assert entry["i5_workflows"] == local["MiSeq i100 Series"]["i5_workflows"]
            assert entry["runinfo_marks_i5_reversed"] is True
            assert "i5_read_orientation" not in entry
            assert "samplesheet_v2_i5_orientation" not in entry
