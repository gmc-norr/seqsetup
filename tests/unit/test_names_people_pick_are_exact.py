"""A name a page shows and a person picks is refused when it begins or ends
with whitespace or holds a hidden character.

Two names that look the same on a page and mean different things is the oldest
index mix-up there is: a kit CSV took ``D701`` and ``D701 `` as two pairs, so
the index panel drew two chips both reading D701 with different sequences, and
an instrument file could list the i5 workflow ``Standard `` beside
``Standard`` with the opposite i5 direction. ``ExactName256``
(``input_rules/base.py``) already held a TestName to this; the same rule now
covers index names, pair names, kit names and versions, instrument names, flow
cell names and i5 workflow names (review OPSDOCS-2, CONFIG-11).
"""

import pytest

from seqsetup.input_rules.instruments import (
    check_local_instruments_file,
    check_synced_instrument_file,
)
from seqsetup.input_rules.kits import check_form_boxes, check_index_kit_file

from .test_input_rules_instruments import LOCAL, ONE, SYNCED
from .test_input_rules_kits import PAIRS, SINGLE

ZWSP = "​"


def _kit_errors(text):
    return [(tuple(p.path), p.message) for p in check_index_kit_file(text, "k.yaml").problems
            if p.level == "error"]


def _instrument_errors(text):
    return [(tuple(p.path), p.message)
            for p in check_synced_instrument_file(text, "one.yaml").problems
            if p.level == "error"]


class TestAKitsNames:

    def test_the_good_files_pass(self):
        assert _kit_errors(SINGLE) == [] and _kit_errors(PAIRS) == []

    @pytest.mark.parametrize("written", ["Probe Kit ", " Probe Kit", "Probe Kit" + ZWSP])
    def test_a_kit_name(self, written):
        paths = [path for path, _ in _kit_errors(SINGLE.replace(
            "name: Probe Kit", f'name: "{written}"', 1))]

        assert paths == [("name",)]

    @pytest.mark.parametrize("written", ["1.0 ", "1.0" + ZWSP])
    def test_a_kit_version(self, written):
        paths = [path for path, _ in _kit_errors(SINGLE.replace(
            "version: '1.0'", f'version: "{written}"'))]

        assert paths == [("version",)]

    @pytest.mark.parametrize("written", ["A ", ZWSP + "A"])
    def test_an_index_name(self, written):
        paths = [path for path, _ in _kit_errors(SINGLE.replace(
            "  - name: A\n", f'  - name: "{written}"\n'))]

        assert paths == [("i7_indexes", 0, "name")]

    @pytest.mark.parametrize("written", ["P1 ", "P1" + ZWSP])
    def test_a_pair_name(self, written):
        paths = [path for path, _ in _kit_errors(PAIRS.replace(
            "  - name: P1\n", f'  - name: "{written}"\n'))]

        assert paths == [("index_pairs", 0, "name")]

    def test_a_name_inside_a_pair(self):
        paths = [path for path, _ in _kit_errors(PAIRS.replace(
            "      name: a\n", '      name: "a "\n'))]

        assert paths == [("index_pairs", 0, "index1", "name")]

    def test_a_space_inside_a_name_is_still_fine(self):
        assert _kit_errors(SINGLE.replace("  - name: A\n", "  - name: A 1\n")) == []


class TestAnInstrumentsNames:

    def test_the_good_file_passes(self):
        assert _instrument_errors(ONE) == []

    @pytest.mark.parametrize("path", SYNCED, ids=lambda p: p.name)
    def test_every_shipped_synced_file_passes(self, path):
        assert [p for p in check_synced_instrument_file(path.read_text(), path.name).problems
                if p.level == "error"] == []

    def test_the_shipped_local_file_passes(self):
        assert [p for p in check_local_instruments_file(LOCAL.read_text(), LOCAL.name).problems
                if p.level == "error"] == []

    @pytest.mark.parametrize("written", ["NovaSeq X Series ", "NovaSeq X Series" + ZWSP])
    def test_an_instrument_name(self, written):
        paths = [path for path, _ in _instrument_errors(
            ONE.replace("\nname: NovaSeq X Series\n", f'\nname: "{written}"\n'))]

        assert paths == [("name",)]

    @pytest.mark.parametrize("written", ["10B ", "10B" + ZWSP])
    def test_a_flow_cell_name(self, written):
        """A flow cell is picked on the run page, and its name decides the
        lanes and the reagent kits the run may have."""
        paths = [path for path, _ in _instrument_errors(
            ONE.replace('  "10B":\n', f'  "{written}":\n'))]

        assert paths == [("flowcells", written)]

    def test_an_i5_workflow_name(self):
        """``Standard `` beside ``Standard`` with the opposite i5 direction
        decides which way every i5 is written into the sheet."""
        paths = [path for path, _ in _instrument_errors(ONE.replace(
            "  - name: Standard\n    i5_read_orientation: forward\n",
            "  - name: Standard\n    i5_read_orientation: forward\n"
            '  - name: "Standard "\n    i5_read_orientation: reverse-complement\n'))]

        assert paths == [("i5_workflows", 1, "name")]

    def test_a_workflow_name_with_a_space_inside_is_still_fine(self):
        assert _instrument_errors(ONE.replace(
            "  - name: Standard\n", "  - name: Standard Flow\n")) == []


class TestTheKitUploadBoxes:

    @pytest.mark.parametrize("box, value", [("kit_name", "K" + ZWSP),
                                            ("kit_version", "1.0" + ZWSP)])
    def test_a_hidden_character_typed_in_a_box(self, box, value):
        said = check_form_boxes(**{box: value})

        assert len(said) == 1 and said[0].startswith(("Kit name:", "Kit version:")), said
