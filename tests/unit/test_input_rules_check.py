"""The strict base, the translator and the check pipeline
(docs/design/2026-10-18-input-rules-design.md, "2. Validate" and "3. Problems").

Pydantic's defaults are relaxed (unknown keys ignored, "1" read as 1); the
strict base refuses both. Pydantic's errors name a location tuple and quote the
input; the translator turns each into a problem with a line, a column and a
plain message of our own.
"""

from typing import Literal, Optional

import pytest

from seqsetup.input_rules.base import (
    STORAGE_MAX_INT,
    Label,
    PlainName,
    StrictRules,
    Text256,
    whole,
)
from seqsetup.input_rules.check import Finding, check_yaml
from seqsetup.input_rules.problems import path_text, problem_line


class Lane(StrictRules):
    lanes: whole(1, 8)
    description: Label = ""


class Workflow(StrictRules):
    name: Text256
    side: Literal["forward", "reverse-complement"]


class Thing(StrictRules):
    name: Text256
    code: PlainName
    enabled: bool
    flowcells: dict[str, Lane]
    workflows: list[Workflow]
    limits: dict[int, whole(1, 600)] = {}
    note: Optional[Text256] = None


GOOD = (
    "name: X\n"
    "code: X_1\n"
    "enabled: true\n"
    "flowcells:\n"
    "  10B:\n"
    "    lanes: 8\n"
    "workflows:\n"
    "  - name: Standard\n"
    "    side: forward\n"
)


def _check(text, rulebook=Thing, **kwargs):
    return check_yaml(text, "f.yaml", rulebook, **kwargs)


def _only(result):
    (problem,) = [p for p in result.problems if p.level == "error"]
    return problem


class TestAGoodFile:

    def test_gives_the_checked_value_and_no_problem(self):
        result = _check(GOOD)

        assert result.problems == [] and result.ok
        assert result.value.flowcells["10B"].lanes == 8
        assert result.value.workflows[0].side == "forward"


class TestUnknownKeys:

    def test_a_misspelt_key_is_refused_at_its_line(self):
        problem = _only(_check(GOOD.replace("    lanes: 8", "    lanes: 8\n    lane: 2")))

        assert problem.path == ("flowcells", "10B", "lane")
        assert (problem.line, problem.column) == (7, 5)
        assert "not a key this file can have" in problem.message

    def test_at_the_top_level_too(self):
        problem = _only(_check(GOOD + "colour_balance_enabled: true\n"))

        assert problem.path == ("colour_balance_enabled",)
        assert problem.line == 10


class TestNoConversions:

    @pytest.mark.parametrize("line, path, says", [
        ("name: 5", ("name",), "must be text"),
        ("enabled: 1", ("enabled",), "true or false"),
        ("code: true", ("code",), "must be text"),
    ])
    def test_a_value_of_another_type_is_refused(self, line, path, says):
        key = line.split(":")[0]
        text = "\n".join(line if row.startswith(key + ":") else row for row in GOOD.splitlines()) + "\n"

        problem = _only(_check(text))

        assert problem.path == path and says in problem.message

    def test_a_quoted_number_is_not_a_whole_number(self):
        problem = _only(_check(GOOD.replace("lanes: 8", "lanes: '8'")))

        assert "whole number" in problem.message

    def test_a_missing_value_says_write_a_value(self):
        problem = _only(_check(GOOD.replace("name: X\n", "name:\n")))

        assert problem.path == ("name",) and "needs a value" in problem.message

    def test_a_default_is_checked_like_a_written_value(self):
        class Bad(StrictRules):
            lanes: whole(1, 8) = 0

        assert not _check("{}\n", Bad).ok


class TestEveryKindOfProblemHasAPlace:

    def test_a_missing_key_points_at_its_map(self):
        problem = _only(_check(GOOD.replace("    lanes: 8\n", "    description: x\n")))

        assert problem.path == ("flowcells", "10B", "lanes")
        assert "is required" in problem.message
        assert problem.line == 6

    def test_a_missing_key_at_the_top_points_at_line_1(self):
        problem = _only(_check(GOOD.replace("code: X_1\n", "")))

        assert problem.path == ("code",) and problem.line == 1

    def test_a_list_item(self):
        problem = _only(_check(GOOD.replace("side: forward", "side: sideways")))

        assert problem.path == ("workflows", 0, "side")
        assert problem.line == 9
        assert "must be one of" in problem.message and "forward" in problem.message

    def test_a_map_key_of_the_wrong_kind(self):
        problem = _only(_check(GOOD + "limits:\n  big: 320\n"))

        assert problem.path == ("limits", "big")
        assert problem.line == 11
        assert "whole number" in problem.message

    def test_a_number_out_of_range(self):
        result = _check(GOOD.replace("lanes: 8", "lanes: 9") + "limits:\n  300: 0\n")

        assert sorted((p.path, p.message) for p in result.problems) == [
            (("flowcells", "10B", "lanes"), "must be at most 8"),
            (("limits", 300), "must be at least 1"),
        ]

    def test_a_building_block_gives_its_own_message(self):
        problem = _only(_check(GOOD.replace("code: X_1", "code: X 1")))

        assert "letters, digits" in problem.message

    def test_a_map_where_a_list_belongs(self):
        problem = _only(_check(GOOD.replace("  - name: Standard\n    side: forward\n", "  x: 1\n")))

        assert problem.path == ("workflows",) and "must be a list" in problem.message

    def test_a_file_that_is_not_a_map(self):
        problem = _only(_check("- a\n- b\n"))

        assert problem.path == () and "map" in problem.message

    def test_an_empty_file(self):
        problem = _only(_check(""))

        assert problem.path == () and "empty" in problem.message

    def test_every_field_error_is_reported_together(self):
        result = _check(GOOD.replace("name: X", "name: 5").replace("lanes: 8", "lanes: 0"))

        assert len(result.problems) == 2


class TestReaderProblemsComeFirst:

    def test_the_rulebook_does_not_run_on_a_file_the_reader_refused(self):
        result = _check(GOOD.replace("lanes: 8", "lanes: 012") + "colour: x\n")

        (problem,) = result.problems
        assert "plain digits" in problem.message


class TestCrossKeyChecks:

    @staticmethod
    def _two(value):
        if value.enabled:
            return [Finding(("code",), "must not be X_1 when enabled"),
                    Finding(("flowcells",), "needs a second flow cell when enabled")]
        return []

    def test_every_check_runs_and_names_its_path(self):
        result = _check(GOOD, cross_checks=[self._two])

        assert [(p.path, p.line) for p in result.problems] == [(("code",), 2), (("flowcells",), 4)]
        assert result.value is None

    def test_no_check_runs_on_a_value_that_failed(self):
        ran = []
        result = _check(GOOD.replace("name: X", "name: 5"), cross_checks=[lambda v: ran.append(v) or []])

        assert ran == []
        assert "further checks" in result.note.lower()


class TestWarnings:

    def test_a_warning_never_blocks(self):
        result = _check(GOOD, warnings=lambda v: [Finding(("name",), "is short")])

        assert result.ok and result.value is not None
        (problem,) = result.problems
        assert problem.level == "warning" and problem.line == 1


class TestSensitiveInputs:

    SECRET = "mongodb://u:s3cret@h/db"

    def test_a_value_is_never_quoted(self):
        result = _check(GOOD.replace("enabled: true", f"enabled: '{self.SECRET}'"))

        assert all(self.SECRET not in p.message for p in result.problems)

    def test_an_unknown_key_that_is_a_secret_is_never_kept(self):
        (problem,) = _check(GOOD + f"'{self.SECRET}': 1\n", sensitive=True).problems

        assert self.SECRET not in repr(problem)
        assert "an unknown key" in problem_line(problem)

    def test_a_key_given_twice_is_not_kept_either(self):
        result = _check(GOOD + f"'{self.SECRET}': 1\n'{self.SECRET}': 2\n", sensitive=True)

        assert result.problems
        assert all(self.SECRET not in repr(p) for p in result.problems)

    def test_the_rulebook_s_own_names_are_shown(self):
        (problem,) = _check(GOOD.replace("lanes: 8", "lanes: 9"), sensitive=True).problems

        assert problem_line(problem).startswith("f.yaml:6:12: flowcells > an unknown key > lanes")


class TestThePathAsAPersonReadsIt:

    def test_keys_and_list_items(self):
        assert path_text(("workflows", 0, "side")) == "workflows > item 1 > side"

    def test_the_whole_file(self):
        assert path_text(()) == "the file"

    def test_one_problem_line(self):
        from seqsetup.input_rules.problems import InputProblem

        line = problem_line(InputProblem("f.yaml", 3, 5, ("a", "b"), "is required"))

        assert line == "f.yaml:3:5: a > b: is required"


class TestBuildingBlocks:

    def test_the_storage_limit(self):
        assert STORAGE_MAX_INT == 2**63 - 1
