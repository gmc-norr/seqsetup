"""The canonical index kit rulebook (docs/design/2026-10-18-input-rules-design.md,
"Step 3: index kit files, every format").

Every kit format reaches one rulebook, so these tests hold the rules once:
what a kit file must write out, what each value may be, and what the mode's
own lists must hold. The format adapters are tested through their parsers
(tests/unit/test_index_parser.py, tests/unit/test_index_kit_sync_parser.py).
"""

import pytest

from seqsetup.input_rules.kits import KIT_LIST_MAX, KitRules, build_kit, check_index_kit_file
from seqsetup.models.index import IndexMode

SINGLE = """name: Probe Kit
version: '1.0'
index_mode: single
i7_indexes:
  - name: A
    sequence: ACGTACGT
"""

PAIRS = """name: Probe Kit
version: '1.0'
index_mode: unique_dual
index_pairs:
  - name: P1
    index1:
      name: a
      sequence: ACGTACGT
    index2:
      name: b
      sequence: TTTTCCCC
"""


def problems(text):
    return [(p.line, tuple(p.path), p.message) for p in check_index_kit_file(text, "k.yaml").problems]


def checked(text):
    result = check_index_kit_file(text, "k.yaml")
    assert result.ok, result.problems
    return result.value


class TestAKitFileWritesItsFactsOut:

    def test_a_single_kit_file_is_accepted(self):
        value = checked(SINGLE)

        assert (value.name, value.version, value.index_mode) == ("Probe Kit", "1.0", "single")
        assert [(i.name, i.sequence) for i in value.i7_indexes] == [("A", "ACGTACGT")]

    @pytest.mark.parametrize("key", ["name", "version", "index_mode"])
    def test_a_missing_required_key_is_refused(self, key):
        text = "\n".join(line for line in SINGLE.splitlines() if not line.startswith(key + ":"))

        assert problems(text + "\n") == [(1, (key,), "is required")]

    def test_an_unknown_key_is_refused_with_its_line(self):
        assert problems(SINGLE + "ownr: someone\n") == [
            (7, ("ownr",), "is not a key this file can have (check the spelling)")]

    @pytest.mark.parametrize("key", ["created_by", "source"])
    def test_the_sync_s_own_fields_are_not_file_keys(self, key):
        (problem,) = problems(SINGLE + f"{key}: me\n")

        assert problem[1] == (key,)
        assert "not a key this file can have" in problem[2]


class TestEachValueHasOneSpelling:

    @pytest.mark.parametrize("written", ["'no'", "'yes'", "'true'", "'maybe'", "1", "0"])
    def test_is_fixed_layout_must_be_true_or_false(self, written):
        (problem,) = problems(SINGLE + f"is_fixed_layout: {written}\n")

        assert problem[1] == ("is_fixed_layout",)
        assert problem[2] == "must be true or false"

    def test_is_fixed_layout_absent_means_false(self):
        assert checked(SINGLE).is_fixed_layout is False

    @pytest.mark.parametrize("written", ["no", "yes"])
    def test_an_unquoted_yes_or_no_is_refused_by_the_reader(self, written):
        (problem,) = problems(SINGLE + f"is_fixed_layout: {written}\n")

        assert "write true or false" in problem[2]

    def test_comments_must_be_text(self):
        (problem,) = problems(SINGLE + "comments: 12\n")

        assert problem[1] == ("comments",)
        assert problem[2] == "must be text: put it in quotes"

    def test_default_index_cycles_must_be_a_whole_number(self):
        (problem,) = problems(SINGLE + "default_index1_cycles: '8'\n")

        assert problem[1] == ("default_index1_cycles",)
        assert problem[2] == "must be a whole number"

    def test_an_index_list_must_be_a_list(self):
        text = "name: K\nversion: '1.0'\nindex_mode: single\ni7_indexes:\n  A: ACGTACGT\n"

        (problem,) = problems(text)

        assert problem[1] == ("i7_indexes",)
        assert problem[2] == "must be a list"

    def test_an_unknown_index_mode_is_refused(self):
        (problem,) = problems(SINGLE.replace("index_mode: single", "index_mode: sngl"))

        assert problem[1] == ("index_mode",)
        assert "must be one of" in problem[2]


class TestEveryTextHasItsBound:
    """A name cut at 256 is another name (CLAUDE.md), so text over its bound
    is refused. models/index.py cuts the kit's four texts today, and an
    index's own name and well position have no cap at all."""

    @pytest.mark.parametrize("key", ["name", "version", "description", "comments"])
    def test_a_kit_text_over_256_characters_is_refused(self, key):
        long = "N" * 257
        text = SINGLE + f"{key}: {long}\n" if key not in ("name", "version") else \
            SINGLE.replace(f"{key}: Probe Kit", f"{key}: {long}").replace(f"{key}: '1.0'", f"{key}: '{long}'")

        (problem,) = problems(text)

        assert problem[1] == (key,)
        assert problem[2] == "must be at most 256 characters"

    @pytest.mark.parametrize("key", ["name", "version", "description", "comments"])
    def test_a_kit_text_of_256_characters_is_accepted(self, key):
        long = "N" * 256
        text = SINGLE + f"{key}: {long}\n" if key not in ("name", "version") else \
            SINGLE.replace(f"{key}: Probe Kit", f"{key}: {long}").replace(f"{key}: '1.0'", f"{key}: '{long}'")

        assert getattr(checked(text), key) == long

    def test_an_index_name_over_256_characters_is_refused(self):
        (problem,) = problems(SINGLE.replace("name: A", "name: " + "Z" * 257))

        assert problem[1] == ("i7_indexes", 0, "name")
        assert problem[2] == "must be at most 256 characters"

    def test_a_well_position_over_256_characters_is_refused(self):
        (problem,) = problems(SINGLE + "    well_position: " + "W" * 257 + "\n")

        assert problem[1] == ("i7_indexes", 0, "well_position")
        assert problem[2] == "must be at most 256 characters"

    @pytest.mark.parametrize("key", ["name", "version"])
    def test_text_of_spaces_only_is_refused(self, key):
        text = SINGLE.replace("name: Probe Kit", "name: '  '") if key == "name" \
            else SINGLE.replace("version: '1.0'", "version: '  '")

        (problem,) = problems(text)

        assert problem[1] == (key,)
        assert problem[2] == "must not be empty"


class TestTheVersionCarriesNoColonOrSlash:
    """The stored _id is name:version, and the version is the last path
    segment of the kit's page, download and Delete. IndexValidator already
    refuses a colon as not a semantic version, with no line; the rulebook
    says it by name and line. A colon in a NAME stays accepted: it is stored
    today, nothing splits a kit_id, and refusing it would orphan the
    index_kit_name on its samples (run DECISIONS Q1)."""

    @pytest.mark.parametrize("written", ["1:0", "1/0", "..", "."])
    def test_a_version_that_cannot_be_an_id_is_refused(self, written):
        (problem,) = problems(SINGLE.replace("version: '1.0'", f"version: '{written}'"))

        assert problem[1] == ("version",)

    def test_a_colon_in_a_name_is_still_accepted(self):
        assert checked(SINGLE.replace("name: Probe Kit", "name: 'Probe: Kit'")).name == "Probe: Kit"

    def test_a_name_made_only_of_dots_is_refused(self):
        (problem,) = problems(SINGLE.replace("name: Probe Kit", "name: '..'"))

        assert problem[1] == ("name",)


class TestASequenceIsDna:

    def test_a_sequence_that_is_not_dna_is_refused(self):
        (problem,) = problems(SINGLE.replace("sequence: ACGTACGT", "sequence: ACGTXCGT"))

        assert problem[1] == ("i7_indexes", 0, "sequence")
        assert "A, C, G, T" in problem[2]

    def test_a_sequence_is_uppercased_and_stripped(self):
        value = checked(SINGLE.replace("sequence: ACGTACGT", "sequence: ' acgtacgt '"))

        assert value.i7_indexes[0].sequence == "ACGTACGT"

    def test_a_block_scalar_sequence_is_accepted(self):
        value = checked(SINGLE.replace("    sequence: ACGTACGT", "    sequence: |\n      ACGTACGT"))

        assert value.i7_indexes[0].sequence == "ACGTACGT"

    def test_an_empty_sequence_is_refused(self):
        (problem,) = problems(SINGLE.replace("sequence: ACGTACGT", "sequence: ''"))

        assert problem[1] == ("i7_indexes", 0, "sequence")

    def test_an_adapter_that_is_not_dna_is_refused(self):
        (problem,) = problems(SINGLE + "adapter_read1: ACGTX\n")

        assert problem[1] == ("adapter_read1",)

    def test_a_sequence_of_1001_bases_is_refused(self):
        (problem,) = problems(SINGLE.replace("sequence: ACGTACGT", "sequence: " + "A" * 1001))

        assert problem[1] == ("i7_indexes", 0, "sequence")
        assert problem[2] == "must be at most 1000 characters"


class TestACycleCountIsWhatARunCanRead:

    @pytest.mark.parametrize("written,ok", [("1", True), ("600", True), ("0", False), ("601", False)])
    def test_the_default_index_cycles_range(self, written, ok):
        text = SINGLE + f"default_index1_cycles: {written}\n"

        if ok:
            assert checked(text).default_index1_cycles == int(written)
        else:
            (problem,) = problems(text)
            assert problem[1] == ("default_index1_cycles",)

    def test_a_read_override_outside_the_alphabet_is_refused(self):
        (problem,) = problems(SINGLE + "default_read1_override: Y*Z\n")

        assert problem[1] == ("default_read1_override",)


class TestEveryPairIsWrittenOut:
    """A pair with no name was stored under the invented name Pair_1, and an
    index inside it took the pair's name."""

    def test_a_pair_file_is_accepted(self):
        value = checked(PAIRS)

        (pair,) = value.index_pairs
        assert (pair.name, pair.index1.name, pair.index2.name) == ("P1", "a", "b")

    def test_a_pair_with_no_name_is_refused(self):
        text = ("name: K\nversion: '1.0'\nindex_mode: unique_dual\nindex_pairs:\n"
                "  - index1:\n      name: a\n      sequence: ACGTACGT\n")

        (problem,) = problems(text)

        assert problem[1] == ("index_pairs", 0, "name")
        assert problem[2] == "is required"

    def test_an_index_inside_a_pair_with_no_name_is_refused(self):
        (problem,) = problems(PAIRS.replace("      name: a\n", ""))

        assert problem[1] == ("index_pairs", 0, "index1", "name")
        assert problem[2] == "is required"

    def test_a_pair_needs_an_i7(self):
        (problem,) = problems(PAIRS.replace("    index1:\n      name: a\n      sequence: ACGTACGT\n", ""))

        assert problem[1] == ("index_pairs", 0, "index1")
        assert problem[2] == "is required"

    def test_a_pair_may_have_no_i5(self):
        value = checked(PAIRS.replace("    index2:\n      name: b\n      sequence: TTTTCCCC\n", ""))

        assert value.index_pairs[0].index2 is None


class TestTheModeSOwnListsHoldTheIndexes:

    def test_a_unique_dual_file_needs_pairs(self):
        text = "name: K\nversion: '1.0'\nindex_mode: unique_dual\nindex_pairs: []\n"

        (problem,) = problems(text)

        assert problem[1] == ("index_pairs",)
        assert "unique_dual" in problem[2]

    def test_a_combinatorial_file_needs_both_lists(self):
        text = ("name: K\nversion: '1.0'\nindex_mode: combinatorial\n"
                "i7_indexes:\n  - name: A\n    sequence: ACGTACGT\n")

        (problem,) = problems(text)

        assert problem[1] == ("i5_indexes",)

    def test_a_non_empty_list_the_mode_does_not_read_is_refused(self):
        text = PAIRS + "i7_indexes:\n  - name: A\n    sequence: ACGTACGT\n"

        (problem,) = problems(text)

        assert problem[1] == ("i7_indexes",)
        assert "unique_dual" in problem[2] and "index_pairs" in problem[2]

    def test_an_empty_list_the_mode_does_not_read_is_accepted(self):
        value = checked(PAIRS + "i7_indexes: []\n")

        assert value.i7_indexes == []


class TestAKitFileHasASize:
    """Nothing bounded a kit's size: 20,000 pairs make a 4.72 MB BSON
    document from a 2.63 MB file, and the sync's 10 MB per-file cap would
    give about 18 MB -- over MongoDB's 16 MiB, after the stored synced kits
    have been deleted."""

    def test_more_indexes_than_the_cap_is_refused(self):
        entries = "".join(f"  - name: A{n}\n    sequence: ACGTACGT\n" for n in range(KIT_LIST_MAX + 1))
        text = f"name: K\nversion: '1.0'\nindex_mode: single\ni7_indexes:\n{entries}"

        (problem,) = problems(text)

        assert problem[1] == ("i7_indexes",)
        assert problem[2] == f"must have at most {KIT_LIST_MAX} item(s)"


class TestTheCheckedValueBecomesTodaySKit:

    def test_the_kit_is_built_from_the_checked_value_only(self):
        kit = build_kit(checked(PAIRS))

        assert (kit.name, kit.version, kit.index_mode) == ("Probe Kit", "1.0", IndexMode.UNIQUE_DUAL)
        assert [(p.id, p.name, p.index1.sequence, p.index2.sequence) for p in kit.index_pairs] == [
            ("Probe Kit_P1", "P1", "ACGTACGT", "TTTTCCCC")]

    def test_the_pair_id_uses_the_name_the_file_gave(self):
        kit = build_kit(checked(PAIRS), kit_name="FormKit")

        assert kit.name == "FormKit"
        assert [p.id for p in kit.index_pairs] == ["Probe Kit_P1"]

    def test_the_sync_s_own_fields_are_set_by_the_caller(self):
        kit = build_kit(checked(SINGLE), created_by="github_sync", source="github")

        assert (kit.created_by, kit.source) == ("github_sync", "github")
