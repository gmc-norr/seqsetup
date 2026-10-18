"""A report of problems kept within a store's size (docs/design/2026-10-18-input-rules-design.md,
"6. Where problems are shown").

The sync status is one MongoDB document and an audit row's details are dropped
whole above 64 KiB, so a long report (100,000 unknown keys) would fill either
and lose everything. A report is cut to a budget in encoded bytes, message
included, and always keeps how many problems there were and how many are left
out.
"""

import bson

from seqsetup.input_rules.problems import (
    InputProblem,
    bounded_report,
    problem_from_record,
    problem_record,
)


def _problem(n, key_length=10):
    return InputProblem(f"instruments/f{n}.yaml", n + 1, 3, ("flowcells", "k" * key_length, n),
                        "is not a key this file can have (check the spelling)")


def _size(report):
    return len(bson.encode({"details": report}))


class TestARecord:

    def test_round_trips(self):
        problem = InputProblem("a.yaml", 4, None, ("limits", 300, "x"), "is required", "warning")

        assert problem_from_record(problem_record(problem)) == problem

    def test_is_plain_data_mongodb_can_store(self):
        bson.encode({"p": problem_record(_problem(1))})


class TestASmallReport:

    def test_keeps_everything(self):
        report = bounded_report("Refused.", [_problem(1), _problem(2)], 32 * 1024)

        assert report["message"] == "Refused."
        assert [problem_from_record(r) for r in report["problems"]] == [_problem(1), _problem(2)]
        assert (report["problem_count"], report["problems_left_out"]) == (2, 0)


class TestALongReport:

    BUDGET = 32 * 1024

    def test_stays_within_its_budget_and_keeps_the_counts(self):
        problems = [_problem(n, key_length=256) for n in range(5000)]

        report = bounded_report("x" * 200_000, problems, self.BUDGET)

        assert _size(report) <= self.BUDGET
        assert report["problem_count"] == 5000
        assert report["problems_left_out"] == 5000 - len(report["problems"])
        assert report["problems"], "some problems still fit"

    def test_a_long_message_is_cut_and_says_so(self):
        report = bounded_report("é" * 100_000, [], self.BUDGET)

        assert _size(report) <= self.BUDGET
        assert report["message"].startswith("é")
        assert report["message"].endswith("[cut: the list of problems has the rest]")

    def test_problems_are_kept_in_order_from_the_start(self):
        problems = [_problem(n, key_length=256) for n in range(500)]

        report = bounded_report("", problems, self.BUDGET)

        kept = [problem_from_record(r) for r in report["problems"]]
        assert kept == problems[:len(kept)]
