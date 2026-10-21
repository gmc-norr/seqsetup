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


# The exact-name rule's own two messages. A test that only counted the path
# would pass on another rule refusing the same text (an instrument name that
# is no instrument SeqSetup has, say), so each case reads the message.
SAYS = ("must not begin or end with a space", "holds a hidden character")


def _only_exact_name(errors, path):
    assert [p for p, _ in errors] == [path], errors
    ((_path, message),) = errors
    assert message.startswith(SAYS), message


class TestAKitsNames:

    def test_the_good_files_pass(self):
        assert _kit_errors(SINGLE) == [] and _kit_errors(PAIRS) == []

    @pytest.mark.parametrize("written", ["Probe Kit ", " Probe Kit", "Probe Kit" + ZWSP])
    def test_a_kit_name(self, written):
        _only_exact_name(_kit_errors(SINGLE.replace(
            "name: Probe Kit", f'name: "{written}"', 1)), ("name",))

    @pytest.mark.parametrize("written", ["1.0 ", "1.0" + ZWSP])
    def test_a_kit_version(self, written):
        _only_exact_name(_kit_errors(SINGLE.replace(
            "version: '1.0'", f'version: "{written}"')), ("version",))

    @pytest.mark.parametrize("written", ["A ", ZWSP + "A"])
    def test_an_index_name(self, written):
        _only_exact_name(_kit_errors(SINGLE.replace(
            "  - name: A\n", f'  - name: "{written}"\n')), ("i7_indexes", 0, "name"))

    @pytest.mark.parametrize("written", ["P1 ", "P1" + ZWSP])
    def test_a_pair_name(self, written):
        _only_exact_name(_kit_errors(PAIRS.replace(
            "  - name: P1\n", f'  - name: "{written}"\n')), ("index_pairs", 0, "name"))

    def test_a_name_inside_a_pair(self):
        _only_exact_name(_kit_errors(PAIRS.replace(
            "      name: a\n", '      name: "a "\n')),
            ("index_pairs", 0, "index1", "name"))

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
        _only_exact_name(_instrument_errors(
            ONE.replace("\nname: NovaSeq X Series\n", f'\nname: "{written}"\n')), ("name",))

    @pytest.mark.parametrize("written", ["10B ", "10B" + ZWSP])
    def test_a_flow_cell_name(self, written):
        """A flow cell is picked on the run page, and its name decides the
        lanes and the reagent kits the run may have."""
        _only_exact_name(_instrument_errors(
            ONE.replace('  "10B":\n', f'  "{written}":\n')), ("flowcells", written))

    def test_an_i5_workflow_name(self):
        """``Standard `` beside ``Standard`` with the opposite i5 direction
        decides which way every i5 is written into the sheet."""
        paths = [path for path, _ in _instrument_errors(ONE.replace(
            "  - name: Standard\n    i5_read_orientation: forward\n",
            "  - name: Standard\n    i5_read_orientation: forward\n"
            '  - name: "Standard "\n    i5_read_orientation: reverse-complement\n'))]

        assert paths == [("i5_workflows", 1, "name")]

    @pytest.mark.parametrize("written", ["NovaSeq X Series ", "NovaSeq X Series" + ZWSP])
    def test_the_name_a_file_of_several_instruments_lists_one_under(self, written):
        """Such a key is refused twice over -- it is no name SeqSetup has
        either (test_instrument_name_is_one_seqsetup_has.py) -- so there is no
        break row of its own for it; what matters is that the file is refused
        and the entry named."""
        from .test_input_rules_instruments import TestDocumentShapes

        text = TestDocumentShapes.MULTI.replace(
            "  NovaSeq X Series:\n", f'  "{written}":\n')

        paths = [path for path, _ in _instrument_errors(text)]

        assert paths == [("instruments", written)]  # by either rule: see the docstring

    def test_a_workflow_name_with_a_space_inside_is_still_fine(self):
        assert _instrument_errors(ONE.replace(
            "  - name: Standard\n", "  - name: Standard Flow\n")) == []


class TestIlluminasOwnTwoShapesTrimBeforeTheRules:
    """A TSV and an Illumina YAML have their cells stripped by the adapter
    (``services/index_parser.py``) before the rulebook sees them, so a name
    with a space at an end is trimmed there rather than refused. The
    guarantee holds all the same: two names that then read alike are refused
    as one name given twice, and a hidden character -- which no strip removes
    -- is refused by the rulebook. The project's own YAML and the CSV, whose
    names reach the rulebook as written, refuse the space itself."""

    @staticmethod
    def _tsv(rows):
        return "\n".join(["[IndexKit]", "Name\tOld kit", "Version\t1.0", "",
                          "[Indices]", "Name\tSequence\tIndexNumber"] + rows)

    @staticmethod
    def _parse(text, filename):
        from seqsetup.models.index import IndexMode
        from seqsetup.services.index_parser import IndexParser

        return IndexParser.parse_from_content(text, filename, index_mode=IndexMode.SINGLE)

    def test_a_tsv_name_with_a_trailing_space_is_trimmed(self):
        kit = self._parse(self._tsv(["D701 \tATTACTCG\t1"]), "k.tsv")

        assert [i.name for i in kit.i7_indexes] == ["D701"]

    def test_two_tsv_names_one_space_apart_are_one_name_given_twice(self):
        with pytest.raises(Exception) as refused:
            self._parse(self._tsv(["D701\tATTACTCG\t1", "D701 \tTCCGGAGA\t1"]), "k.tsv")

        assert "twice" in str(refused.value), refused.value

    def test_a_tsv_name_with_a_hidden_character_is_refused(self):
        with pytest.raises(Exception) as refused:
            self._parse(self._tsv([f"D701{ZWSP}\tATTACTCG\t1"]), "k.tsv")

        assert "hidden character" in str(refused.value), refused.value

    def test_an_illumina_yaml_name_with_a_trailing_space_is_trimmed(self):
        kit = self._parse("Name: K\nVersion: '1.0'\nIndexSequences:\n"
                          "  i7Index1:\n    'D701 ': ATTACTCG\n", "k.yaml")

        assert [i.name for i in kit.i7_indexes] == ["D701"]

    def test_two_illumina_yaml_names_one_space_apart_are_one_name_given_twice(self):
        with pytest.raises(Exception) as refused:
            self._parse("Name: K\nVersion: '1.0'\nIndexSequences:\n  i7Index1:\n"
                        "    D701: ATTACTCG\n    'D701 ': TCCGGAGA\n", "k.yaml")

        assert "twice" in str(refused.value), refused.value

    def test_an_illumina_yaml_name_with_a_hidden_character_is_refused(self):
        with pytest.raises(Exception) as refused:
            self._parse("Name: K\nVersion: '1.0'\nIndexSequences:\n  i7Index1:\n"
                        f"    'D701{ZWSP}': ATTACTCG\n", "k.yaml")

        assert "hidden character" in str(refused.value), refused.value


class TestTheKitUploadBoxes:

    @pytest.mark.parametrize("box, value", [("kit_name", "K" + ZWSP),
                                            ("kit_version", "1.0" + ZWSP)])
    def test_a_hidden_character_typed_in_a_box(self, box, value):
        said = check_form_boxes(**{box: value})

        assert len(said) == 1 and said[0].startswith(("Kit name:", "Kit version:")), said
