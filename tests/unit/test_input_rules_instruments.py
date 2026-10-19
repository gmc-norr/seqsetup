"""The instrument rulebook (docs/design/2026-10-18-input-rules-design.md,
"Step 1: the core and instrument files").

Instrument files decide lanes, the colour balance check and the i5 direction of
every Sample Sheet. Every key is checked, an unknown one is refused (``lane:``
once gave a flow cell one lane, ``colour_balance_enabled`` left the colour
balance check off), and a fact that changes a sheet or a check must be written
out rather than fall back to a default.
"""

from pathlib import Path

import bson
import pytest
import yaml

from seqsetup.input_rules.instruments import (
    check_local_instruments_file,
    check_synced_instrument_file,
    definitions_from,
    duplicate_instruments,
    local_config,
)
from seqsetup.models.instrument_definition import InstrumentDefinition, OLD_I5_KEY_MESSAGE

CONFIG = Path(__file__).resolve().parents[2] / "config"
SYNCED = sorted((CONFIG / "instruments").glob("*.yaml"))
LOCAL = CONFIG / "instruments.yaml"

ONE = """\
version: "1.0.0"
name: Test Seq
samplesheet_name: TestSeq
chemistry_type: 2-color
has_dragen_onboard: false
i5_workflows:
  - name: Standard
    i5_read_orientation: forward
runinfo_marks_i5_reversed: false
color_balance_enabled: true
dye_channels: ["Blue", "Green"]
base_colors:
  A: "Blue"
  C: "Blue+Green"
  T: "Green"
  G: "Dark"
channel1_name: "Blue"
channel1_bases: ["A", "C"]
channel2_name: "Green"
channel2_bases: ["C", "T"]
dark_base: "G"
onboard_applications:
  BCLConvert:
    software_version: "4.3.6"
flowcells:
  "10B":
    lanes: 8
    reads: 1000
    reagent_kits: [100, 200, 300]
    description: "ten billion"
"""

COLOUR_KEYS = ("dye_channels", "base_colors", "channel1_name", "channel1_bases",
               "channel2_name", "channel2_bases", "dark_base")


def _synced(text, file="one.yaml"):
    return check_synced_instrument_file(text, file)


def _without(text, key):
    """The text with a top-level key and its indented block taken out."""
    out, skipping = [], False
    for row in text.splitlines(keepends=True):
        if row.startswith(f"{key}:"):
            skipping = True
            continue
        if skipping and (row.startswith((" ", "-", "#")) or not row.strip()):
            continue
        skipping = False
        out.append(row)
    return "".join(out)


def _errors(result):
    return [(p.path, p.message) for p in result.problems if p.level == "error"]


def _only(result):
    (error,) = [p for p in result.problems if p.level == "error"]
    return error


class TestTheShippedFiles:

    @pytest.mark.parametrize("path", SYNCED, ids=lambda p: p.name)
    def test_every_shipped_synced_file_passes(self, path):
        result = _synced(path.read_text(), path.name)

        assert _errors(result) == []

    def test_the_shipped_local_file_passes(self):
        result = check_local_instruments_file(LOCAL.read_text(), LOCAL.name)

        assert _errors(result) == []

    def test_a_good_file_passes(self):
        assert _errors(_synced(ONE)) == []


class TestUnknownKeys:

    def test_a_misspelt_lanes_in_a_flow_cell(self):
        error = _only(_synced(ONE.replace("    lanes: 8", "    lanes: 8\n    lane: 2")))

        assert error.path == ("flowcells", "10B", "lane")
        assert error.line == ONE.splitlines().index("    lanes: 8") + 2

    def test_a_misspelt_colour_balance(self):
        error = _only(_synced(ONE + "colour_balance_enabled: false\n"))

        assert error.path == ("colour_balance_enabled",)
        assert "not a key" in error.message

    @pytest.mark.parametrize("key", ["i5_read_orientation", "samplesheet_v2_i5_orientation"])
    def test_an_old_i5_key_gets_its_own_message(self, key):
        error = _only(_synced(ONE + f"{key}: forward\n"))

        assert error.path == (key,) and error.message == OLD_I5_KEY_MESSAGE


class TestFactsMustBeWrittenOut:

    @pytest.mark.parametrize("key", [
        "version", "name", "samplesheet_name", "chemistry_type", "has_dragen_onboard",
        "i5_workflows", "runinfo_marks_i5_reversed", "color_balance_enabled",
        "onboard_applications", "flowcells",
    ])
    def test_a_required_key_left_out(self, key):
        result = _synced(_without(ONE, key))

        assert ((key,), "is required") in _errors(result)

    @pytest.mark.parametrize("key", ["lanes", "reagent_kits"])
    def test_a_required_flow_cell_key_left_out(self, key):
        text = "".join(row for row in ONE.splitlines(keepends=True) if not row.startswith(f"    {key}:"))

        assert (("flowcells", "10B", key), "is required") in _errors(_synced(text))

    @pytest.mark.parametrize("key", ["reads", "description"])
    def test_a_label_may_be_left_out(self, key):
        text = "".join(row for row in ONE.splitlines(keepends=True) if not row.startswith(f"    {key}:"))

        assert _errors(_synced(text)) == []

    def test_an_empty_kit_list_is_written_out_and_means_no_kit_limit(self):
        assert _errors(_synced(ONE.replace("[100, 200, 300]", "[]"))) == []

    def test_samplesheet_versions_is_the_one_named_exception(self):
        (instrument,) = definitions_from(_synced(ONE).value, "one.yaml")

        assert instrument.samplesheet_versions == [2]


class TestValues:

    @pytest.mark.parametrize("old, new, path, says", [
        ("chemistry_type: 2-color", "chemistry_type: 5-color", ("chemistry_type",), "must be one of"),
        ("samplesheet_name: TestSeq", "samplesheet_name: Test Seq", ("samplesheet_name",), "letters, digits"),
        ("has_dragen_onboard: false", "has_dragen_onboard: 0", ("has_dragen_onboard",), "true or false"),
        ("    lanes: 8", "    lanes: 0", ("flowcells", "10B", "lanes"), "at least 1"),
        ("    lanes: 8", "    lanes: 9", ("flowcells", "10B", "lanes"), "at most 8"),
        ("[100, 200, 300]", "[100, 2001]", ("flowcells", "10B", "reagent_kits", 1), "at most 2000"),
        ("[100, 200, 300]", "[0]", ("flowcells", "10B", "reagent_kits", 0), "at least 1"),
        ("    reads: 1000", "    reads: -1", ("flowcells", "10B", "reads"), "at least 0"),
        ("    reads: 1000", f"    reads: {2**63}", ("flowcells", "10B", "reads"), "at most"),
        ('    software_version: "4.3.6"', "    software_version: 4.3.6 beta",
         ("onboard_applications", "BCLConvert", "software_version"), "letters, digits"),
        ('dark_base: "G"', 'dark_base: "U"', ("dark_base",), "must be one of"),
        ('channel1_bases: ["A", "C"]', 'channel1_bases: ["A", "X"]', ("channel1_bases", 1), "must be one of"),
    ])
    def test_a_wrong_value(self, old, new, path, says):
        assert old in ONE
        error = _only(_synced(ONE.replace(old, new)))

        assert error.path == path and says in error.message

    def test_a_kit_listed_twice(self):
        error = _only(_synced(ONE.replace("[100, 200, 300]", "[100, 100]")))

        assert error.path == ("flowcells", "10B", "reagent_kits") and "twice" in error.message

    def test_an_application_that_is_not_illumina_s(self):
        error = _only(_synced(ONE.replace("  BCLConvert:", "  BclConvert:")))

        assert error.path == ("onboard_applications", "BclConvert")
        assert "Illumina" in error.message

    def test_an_application_needs_its_software_version(self):
        error = _only(_synced(ONE.replace('    software_version: "4.3.6"\n', "    {}\n").replace(
            "  BCLConvert:\n    {}", "  BCLConvert: {}")))

        assert error.path == ("onboard_applications", "BCLConvert", "software_version")

    @pytest.mark.parametrize("versions, says", [
        ("[1, 2]", None), ("[2]", None), ("[3]", "at most 2"), ("[]", "at least 1"),
        ("[2, 2]", "twice"), ("[true, 2]", "whole number"),
    ])
    def test_samplesheet_versions(self, versions, says):
        result = _synced(ONE + f"samplesheet_versions: {versions}\n")

        if says is None:
            assert _errors(result) == []
        else:
            assert any(says in message for _, message in _errors(result))

    def test_base_colors_names_exactly_the_four_bases(self):
        result = _synced(ONE.replace('  G: "Dark"\n', ""))

        assert any(path == ("base_colors",) for path, _ in _errors(result))


class TestTheI5Workflows:

    def test_a_name_listed_twice_ignoring_case(self):
        text = ONE.replace(
            "    i5_read_orientation: forward\n",
            "    i5_read_orientation: forward\n  - name: standard\n    i5_read_orientation: forward\n")

        error = _only(_synced(text))

        assert error.path == ("i5_workflows", 1, "name") and "twice" in error.message

    def test_an_orientation_that_is_not_one_of_the_two(self):
        error = _only(_synced(ONE.replace("i5_read_orientation: forward", "i5_read_orientation: reverse")))

        assert error.path == ("i5_workflows", 0, "i5_read_orientation")

    def test_a_name_that_breaks_the_rule(self):
        error = _only(_synced(ONE.replace("  - name: Standard", "  - name: '-bad'")))

        assert error.path == ("i5_workflows", 0, "name")

    def test_no_workflow_at_all(self):
        text = _without(ONE, "i5_workflows") + "i5_workflows: []\n"

        assert any(path == ("i5_workflows",) for path, _ in _errors(_synced(text)))


class TestTheColourFields:

    def test_each_is_required_with_colour_balance_on_a_2_color_instrument(self):
        for key in COLOUR_KEYS:
            result = _synced(_without(ONE, key))
            assert ((key,), "is required when colour balance is on (color_balance_enabled: true)") in _errors(result), key

    @pytest.mark.parametrize("key, written", [
        ("dye_channels", '["Blue", "Green"]'), ("channel1_bases", '["A", "C"]'), ("channel2_bases", '["C", "T"]'),
    ])
    def test_an_empty_list_is_not_the_fact_with_colour_balance_on(self, key, written):
        """An empty list once switched the dark-cycle check off with no word."""
        assert f"{key}: {written}" in ONE

        result = _synced(ONE.replace(f"{key}: {written}", f"{key}: []"))

        assert _errors(result) == [
            ((key,), "must not be empty when colour balance is on (color_balance_enabled: true)")]

    def test_none_is_needed_with_colour_balance_off(self):
        text = ONE.replace("color_balance_enabled: true", "color_balance_enabled: false")
        for key in COLOUR_KEYS:
            text = _without(text, key)

        assert _errors(_synced(text)) == []

    def test_they_are_still_checked_with_colour_balance_off(self):
        text = ONE.replace("color_balance_enabled: true", "color_balance_enabled: false")

        error = _only(_synced(text.replace('dark_base: "G"', 'dark_base: "U"')))

        assert error.path == ("dark_base",)

    def test_each_is_refused_on_a_4_color_instrument(self):
        text = ONE.replace("chemistry_type: 2-color", "chemistry_type: 4-color").replace(
            "color_balance_enabled: true", "color_balance_enabled: false")

        refused = {path for path, _ in _errors(_synced(text))}

        assert refused == {(key,) for key in COLOUR_KEYS}

    def test_an_unusual_dye_channel_is_a_warning(self):
        result = _synced(ONE.replace('["Blue", "Green"]', '["Blue", "Teal"]'))

        assert _errors(result) == []
        (warning,) = [p for p in result.problems if p.level == "warning"]
        assert warning.path == ("dye_channels", 1)


class TestReagentKitMaxCycles:

    def test_a_limit_below_its_kit(self):
        error = _only(_synced(ONE + "reagent_kit_max_cycles:\n  300: 299\n"))

        assert error.path == ("reagent_kit_max_cycles", "300")
        assert error.line == len(ONE.splitlines()) + 2

    def test_a_kit_no_flow_cell_offers_is_a_warning(self):
        result = _synced(ONE + "reagent_kit_max_cycles:\n  600: 620\n")

        assert _errors(result) == []
        assert [p.path for p in result.problems] == [("reagent_kit_max_cycles", "600")]


class TestDocumentShapes:

    MULTI = "instruments:\n  Test Seq:\n" + "".join(
        "    " + row if row.strip() else row
        for row in ONE.splitlines(keepends=True) if not row.startswith("name:"))

    def test_a_multi_instrument_file(self):
        result = _synced(self.MULTI)

        assert _errors(result) == []
        (instrument,) = definitions_from(result.value, "multi.yaml")
        assert instrument.name == "Test Seq"

    def test_a_key_beside_instruments_is_refused(self):
        error = _only(_synced(self.MULTI + "comment: x\n"))

        assert error.path == ("comment",)

    def test_a_name_that_differs_from_its_map_key_is_refused(self):
        text = self.MULTI.replace("  Test Seq:\n", "  Test Seq:\n    name: Other Seq\n")

        error = _only(_synced(text))

        assert error.path == ("instruments", "Test Seq", "name")

    def test_a_name_that_matches_its_map_key_is_fine(self):
        text = self.MULTI.replace("  Test Seq:\n", "  Test Seq:\n    name: Test Seq\n")

        assert _errors(_synced(text)) == []

    def test_a_problem_inside_one_names_the_instrument(self):
        error = _only(_synced(self.MULTI.replace("lanes: 8", "lanes: 9")))

        assert error.path == ("instruments", "Test Seq", "flowcells", "10B", "lanes")

    def test_a_version_is_required_in_each_synced_instrument(self):
        text = self.MULTI.replace('    version: "1.0.0"\n', "")

        assert (("instruments", "Test Seq", "version"), "is required") in _errors(_synced(text))


class TestTheLocalFile:

    def _local(self, text):
        return check_local_instruments_file(text, "instruments.yaml")

    def test_an_entry_needs_no_version(self):
        raw = yaml.safe_load(LOCAL.read_text())
        assert all("version" not in entry for entry in raw["instruments"].values())

        assert _errors(self._local(LOCAL.read_text())) == []

    @pytest.mark.parametrize("key", ["instruments", "default_cycles", "index_cycle_options"])
    def test_each_top_level_key_is_required(self, key):
        result = self._local(_without(LOCAL.read_text(), key))

        assert ((key,), "is required") in _errors(result)

    @pytest.mark.parametrize("old, new, says", [
        ("read1: 18", "read1: 0", "at least 1"),
        ("read1: 18", "read1: 601", "at most 600"),
        ("index1: 8", "index1: 601", "at most 600"),
    ])
    def test_default_cycles_ranges(self, old, new, says):
        text = LOCAL.read_text()
        assert old in text

        result = self._local(text.replace(old, new, 1))

        assert any(path[0] == "default_cycles" and says in message for path, message in _errors(result))

    def test_read_2_and_the_indexes_may_be_0(self):
        text = LOCAL.read_text()
        assert "read2: 18" in text and "index2: 8" in text

        text = text.replace("read2: 18", "read2: 0", 1).replace("index2: 8", "index2: 0", 1)

        assert _errors(self._local(text)) == []

    @pytest.mark.parametrize("options, says", [
        ("[]", "at least 1"), ("[0, 8]", "at least 1"), ("[8, 601]", "at most 600"), ("[8, 8]", "twice"),
    ])
    def test_index_cycle_options(self, options, says):
        text = _without(LOCAL.read_text(), "index_cycle_options") + f"index_cycle_options: {options}\n"

        assert any(path[0] == "index_cycle_options" and says in message
                   for path, message in _errors(self._local(text)))

    def test_an_anchor_is_refused(self):
        result = self._local(LOCAL.read_text().replace("index_cycle_options:", "index_cycle_options: &x"))

        assert any("anchor" in message for _, message in _errors(result))

    def test_the_converted_file_is_the_file_as_written(self):
        result = self._local(LOCAL.read_text())

        assert local_config(result.value) == yaml.safe_load(LOCAL.read_text())


class TestValuesSurviveConversionAndStorage:

    @pytest.mark.parametrize("path", SYNCED, ids=lambda p: p.name)
    def test_a_shipped_file_through_the_model_mongodb_and_back(self, path):
        raw = yaml.safe_load(path.read_text())
        (instrument,) = definitions_from(_synced(path.read_text(), path.name).value, path.name)

        stored = InstrumentDefinition.from_dict(bson.decode(bson.encode(instrument.to_dict())))

        assert stored.to_dict() == instrument.to_dict()
        for key, value in raw.items():
            if key in ("flowcells", "onboard_applications"):
                continue
            assert getattr(stored, key) == (tuple(
                type(stored.i5_workflows[0])(**w) for w in value) if key == "i5_workflows" else value), key
        assert {fc.name: fc.to_dict() | {"name": None} for fc in stored.flowcells} == {
            name: {"name": None, "lanes": fc["lanes"], "reads": fc.get("reads", 0),
                   "reagent_kits": fc["reagent_kits"], "description": fc.get("description", "")}
            for name, fc in raw["flowcells"].items()}
        assert {a.name: a.software_version for a in stored.onboard_applications} == {
            name: app["software_version"] for name, app in raw["onboard_applications"].items()}

    def test_the_largest_values_each_range_allows(self):
        text = (ONE.replace("    lanes: 8", "    lanes: 8")
                .replace("    reads: 1000", f"    reads: {2**63 - 1}")
                .replace("[100, 200, 300]", "[1, 2000]")
                + "reagent_kit_max_cycles:\n  2000: 2400\n  1: 1\n")
        (instrument,) = definitions_from(_synced(text).value, "one.yaml")

        stored = InstrumentDefinition.from_dict(bson.decode(bson.encode(instrument.to_dict())))

        assert stored.flowcells[0].reads == 2**63 - 1
        assert stored.flowcells[0].reagent_kits == [1, 2000]
        assert stored.reagent_kit_max_cycles == {2000: 2400, 1: 1}


class TestTheSyncStoresWhatTheFileSays:
    """What the sync builds from a checked file is what the model builds from
    the file read plainly: a key the file leaves out is not filled in by the
    rulebook (a 4-color file's colour fields stay unset)."""

    @staticmethod
    def _comparable(instrument):
        return {k: v for k, v in instrument.to_dict().items() if k not in ("id", "synced_at")}

    @pytest.mark.parametrize("path", SYNCED, ids=lambda p: p.name)
    def test_a_shipped_file(self, path):
        (checked,) = definitions_from(_synced(path.read_text(), path.name).value, path.name)
        plain = InstrumentDefinition.from_yaml(yaml.safe_load(path.read_text()), path.name)

        assert self._comparable(checked) == self._comparable(plain)


class TestTheEightLocalEntriesThatGainedHasDragenOnboard:
    """They read as false before (every reader defaults to False) and say false now."""

    EIGHT = ("NextSeq 500/550", "MiniSeq", "NovaSeq 6000", "GAIIx", "HiSeq 2000/2500",
             "HiSeq 4000", "HiSeq X", "MiSeq")

    @pytest.mark.parametrize("name", EIGHT)
    def test_the_instrument_is_the_same_with_and_without_it(self, name):
        entry = yaml.safe_load(LOCAL.read_text())["instruments"][name]
        assert entry["has_dragen_onboard"] is False
        before = {key: value for key, value in entry.items() if key != "has_dragen_onboard"}

        def built(data):
            facts = InstrumentDefinition.from_yaml({**data, "name": name}, "instruments.yaml").to_dict()
            return {key: value for key, value in facts.items() if key not in ("id", "synced_at")}

        assert built(before) == built(entry)


class TestTheLocalFileAndTheSyncedFilesAgree:

    def test_each_local_instrument_states_what_its_synced_twin_states(self):
        local = yaml.safe_load(LOCAL.read_text())["instruments"]
        twins = {yaml.safe_load(p.read_text())["name"]: yaml.safe_load(p.read_text()) for p in SYNCED}

        assert set(local) == set(twins)
        for name, entry in local.items():
            twin = {k: v for k, v in twins[name].items() if k not in ("name", "version")}
            assert entry == twin, name


class TestTwoFilesForOneInstrument:

    def test_a_name_or_samplesheet_name_given_by_two_files(self):
        a = definitions_from(_synced(ONE, "a.yaml").value, "a.yaml")
        b = definitions_from(_synced(ONE, "b.yaml").value, "b.yaml")

        problems = duplicate_instruments(a + b)

        assert len(problems) == 2
        assert all("a.yaml" in p and "b.yaml" in p for p in problems)
