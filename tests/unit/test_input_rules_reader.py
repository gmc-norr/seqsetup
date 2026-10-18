"""The YAML reader every settings file goes through (docs/design/2026-10-18-input-rules-design.md, "1. Read").

YAML changes values on its own before any check sees them (012 is 10, 1:20 is
80, yes is True, a tag turns "012" into 10), merges keys that read alike, and
expands anchors. The reader takes one plain spelling per kind of value, refuses
the rest, and records where every key, value and list item came from, so each
problem can name its line and column.
"""

import pytest

from seqsetup.input_rules.reader import MAX_PROBLEMS_PER_FILE, read_yaml


def _read(text, **kwargs):
    return read_yaml(text, "f.yaml", **kwargs)


def _messages(result):
    return [problem.message for problem in result.problems]


class TestPlainValuesAreRead:

    def test_maps_lists_text_whole_numbers_and_yes_no(self):
        result = _read("a: 1\nb: -5\nc: 0\nd: [x, 'y', \"012\"]\ne: {f: true, g: False, h: TRUE}\n")

        assert result.problems == []
        assert result.data == {
            "a": 1, "b": -5, "c": 0, "d": ["x", "y", "012"],
            "e": {"f": True, "g": False, "h": True},
        }

    def test_quoted_values_stay_text(self):
        result = _read("a: '1.10'\nb: \"yes\"\nc: '2026-10-18'\nd: '0x10'\n")

        assert result.data == {"a": "1.10", "b": "yes", "c": "2026-10-18", "d": "0x10"}

    def test_a_missing_value_is_read_as_none_for_the_rulebook_to_judge(self):
        assert _read("a: ~\nb:\nc: null\n").data == {"a": None, "b": None, "c": None}

    def test_an_empty_file_is_none(self):
        result = _read("")

        assert (result.data, result.problems) == (None, [])

    def test_block_text_stays_text(self):
        assert _read("a: |\n  012\n").data == {"a": "012\n"}


class TestOnlyPlainSpellingsOfNumbers:

    @pytest.mark.parametrize("spelling", ["0o17", "1e3", "1.0e3"])
    def test_what_yaml_leaves_as_text_stays_text(self, spelling):
        """YAML 1.1 reads these as text, unchanged; a number field refuses them."""
        assert _read(f"a: {spelling}\n").data == {"a": spelling}

    @pytest.mark.parametrize("spelling", ["012", "0x10", "0b11", "1_000", "1:20", "+5"])
    def test_a_whole_number_written_another_way_is_refused(self, spelling):
        result = _read(f"lanes: {spelling}\n")

        assert result.data is None
        (problem,) = result.problems
        assert problem.path == ("lanes",)
        assert (problem.line, problem.column) == (1, 8)
        assert "plain digits" in problem.message

    @pytest.mark.parametrize("spelling", ["1.10", "1.0", ".5", "1.0e+3", ".inf", ".NaN"])
    def test_a_decimal_number_is_refused_with_put_it_in_quotes(self, spelling):
        (problem,) = _read(f"version: {spelling}\n").problems

        assert "decimal number" in problem.message and "quotes" in problem.message

    @pytest.mark.parametrize("spelling", ["yes", "No", "on", "OFF"])
    def test_yes_no_on_off_are_refused(self, spelling):
        (problem,) = _read(f"enabled: {spelling}\n").problems

        assert "true or false" in problem.message

    @pytest.mark.parametrize("spelling", ["2026-10-18", "2026-10-18 10:00:00"])
    def test_a_date_or_time_is_refused(self, spelling):
        (problem,) = _read(f"when: {spelling}\n").problems

        assert "date" in problem.message and "quotes" in problem.message


class TestNoTags:

    @pytest.mark.parametrize("text", [
        'lanes: !!int "012"\n',
        'on: !!bool "yes"\n',
        "a: !!str 5\n",
        "a: !!float 1\n",
        "a: !!binary aGVsbG8=\n",
        "a: !!set {x, y}\n",
        "a: !!omap [x: 1]\n",
        "a: !!timestamp '2026-10-18'\n",
        "a: ! 5\n",
        "a: !local x\n",
        "a: !!map {x: 1}\n",
        "a: !!seq [1]\n",
    ])
    def test_every_explicit_tag_is_refused(self, text):
        result = _read(text)

        assert result.data is None
        assert any("tag" in message for message in _messages(result))


class TestNoAnchorsAliasesOrMergeKeys:

    def test_every_anchor_and_alias_is_reported(self):
        result = _read("a: &x 1\nb: *x\nc: &y [1]\nd: *y\n")

        messages = _messages(result)
        assert sum("anchor" in m for m in messages) == 2
        assert sum("alias" in m for m in messages) == 2
        assert result.data is None

    def test_an_alias_is_never_expanded(self):
        lol = "a: &a [1,1,1,1,1,1,1,1,1]\n" + "".join(
            f"{chr(98 + i)}: &{chr(98 + i)} [{', '.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(8))

        result = _read(lol)

        assert result.data is None and result.problems

    def test_a_merge_key_is_refused(self):
        result = _read("a:\n  <<: {x: 1}\n  y: 2\n")

        assert any("merge" in m for m in _messages(result))


class TestAKeyGivenTwice:

    def test_is_refused_naming_both_lines(self):
        (problem,) = _read("a: 1\nb: 2\na: 3\n").problems

        assert problem.path == ("a",)
        assert problem.line == 3
        assert "twice" in problem.message and "line 1" in problem.message

    def test_every_repeat_is_reported(self):
        result = _read("a: 1\na: 2\nb:\n  c: 1\n  c: 2\n")

        assert [p.path for p in result.problems] == [("a",), ("b", "c")]

    def test_two_spellings_of_one_key_are_one_key(self):
        """1 and true are one key once read, and so are a plain and a quoted a."""
        result = _read("1: x\ntrue: y\n'a': 1\na: 2\n")

        assert len(result.problems) == 2
        assert all("twice" in m for m in _messages(result))

    def test_a_number_key_and_a_text_key_are_two_keys(self):
        assert _read("10: x\n'10': y\n").data == {10: "x", "10": "y"}

    def test_a_key_that_is_not_a_plain_value_is_refused(self):
        result = _read("? [a, b]\n: 1\n")

        assert any("key" in m for m in _messages(result))


class TestLocations:

    TEXT = (
        "name: X\n"
        "flowcells:\n"
        "  10B:\n"
        "    lanes: 8\n"
        "workflows:\n"
        "  - name: Standard\n"
        "    side: forward\n"
    )

    def test_a_key_and_its_value(self):
        locations = _read(self.TEXT).locations

        assert locations.key(("flowcells", "10B", "lanes")) == (4, 5)
        assert locations.value(("flowcells", "10B", "lanes")) == (4, 12)

    def test_a_list_item_and_a_key_inside_it(self):
        locations = _read(self.TEXT).locations

        assert locations.value(("workflows", 0)) == (6, 5)
        assert locations.key(("workflows", 0, "side")) == (7, 5)

    def test_a_map_key_that_is_a_number_is_found_by_its_text(self):
        locations = _read("limits:\n  300: 320\n").locations

        assert locations.key(("limits", "300")) == (2, 3)
        assert locations.key(("limits", 300)) == (2, 3)

    def test_the_top_of_the_file_is_line_1(self):
        assert _read(self.TEXT).locations.value(()) == (1, 1)


class TestSyntaxErrors:

    def test_two_unclosed_lists_on_one_line_differ_by_column(self):
        first = _read("a: [1, 2\n").problems
        second = _read("a: [1], b: [2\n").problems

        assert len(first) == 1 and len(second) == 1
        assert (first[0].line, first[0].column) != (second[0].line, second[0].column)

    def test_the_message_is_ours_never_the_parsers(self):
        (problem,) = _read("a: [1, 2\nb: c\n").problems

        assert "not closed" in problem.message
        assert "expected" not in problem.message and "got" not in problem.message

    def test_a_tab_gets_its_own_explanation(self):
        (problem,) = _read("a:\n\tb: 1\n").problems

        assert "tab" in problem.message.lower()

    def test_a_secret_in_a_broken_line_is_never_repeated(self):
        result = _read("uri: mongodb://u:s3cret@h/db: [\n")

        assert result.problems
        assert all("s3cret" not in m for m in _messages(result))

    def test_more_than_one_document_is_refused(self):
        (problem,) = _read("a: 1\n---\nb: 2\n").problems

        assert "more than one" in problem.message


class TestValuesShownOnlyWhenSafe:

    def test_a_value_is_quoted_when_the_file_allows_it(self):
        (problem,) = _read("version: 1.10\n", values_safe=True).problems

        assert "1.10" in problem.message

    def test_a_value_is_never_quoted_by_default(self):
        (problem,) = _read("password: 0x5ec7e7\n").problems

        assert "5ec7e7" not in problem.message


class TestAProblemCapPerFile:

    def test_a_file_stops_at_the_cap_and_counts_the_rest(self):
        text = "a: 1\n" + "a: 1\n" * (MAX_PROBLEMS_PER_FILE + 500)

        result = _read(text)

        assert len(result.problems) == MAX_PROBLEMS_PER_FILE + 1
        assert "500 more" in result.problems[-1].message
