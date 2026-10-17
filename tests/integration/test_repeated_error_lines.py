"""A message repeated once per sample is listed once, with how many times.

A practice deploy (2026-10-17) refused Mark Ready with "16 errors to fix
first" and then 16 lines that were 2 messages, each repeated for every one of
8 samples: an application profile problem is reported once per sample that
uses the profile, and its message names no sample. The Mark Ready refusal and
the Check panel now list each message once, with the count; the number of
errors stays the count of every error.
"""

from types import SimpleNamespace

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import SequencingRun
from seqsetup.services.validation_summary import grouped_messages
from seqsetup.templating import templates

# Without quotes, so the rendered HTML holds them as written (a quote is escaped).
A = "Application BCLConvert version 4.1.23 is not available on NovaSeq X Series."
B = "Application DragenGermline version 4.1.23 is not available on NovaSeq X Series."


def _run() -> SequencingRun:
    run = SequencingRun(id="repeats", run_name="Repeats")
    run.add_sample(Sample(sample_id="S1", lanes=[1]))
    return run


def _refusal(messages: list[str]) -> str:
    return templates.env.get_template("runs/_ready_refused.html").render(
        run=_run(), messages=messages)


def _panel(lines: list[str]) -> str:
    # What the panel reads of a ValidationResult, for a run with these errors.
    result = SimpleNamespace(error_count=len(lines), color_balance_enabled=False,
                             color_balance_issue_count=0, color_balance_error_lanes=[])
    return templates.env.get_template("runs/_validate_panel.html").render(
        run=_run(), validation_result=result, error_lines=lines, sample_errors={},
        waiting=False)


class TestGroupedMessages:

    def test_each_message_once_in_the_order_first_seen_with_its_count(self):
        assert grouped_messages([A, B, A, B, A]) == [(A, 3), (B, 2)]

    def test_no_message_is_lost(self):
        lines = [A, B, A, "one", B, A]
        assert sum(times for _m, times in grouped_messages(lines)) == len(lines)

    def test_nothing_gives_nothing(self):
        assert grouped_messages([]) == []


class TestTheMarkReadyRefusal:

    def test_a_repeated_message_is_one_line_with_its_count(self):
        html = _refusal([A, B] * 8)
        assert html.count(A) == 1 and html.count(B) == 1
        assert f"<li>{A} (8 times)</li>" in html
        assert f"<li>{B} (8 times)</li>" in html

    def test_the_heading_still_counts_every_error(self):
        assert "Cannot mark ready: 16 errors to fix first." in _refusal([A, B] * 8)

    def test_a_message_said_once_has_no_count(self):
        assert f"<li>{A}</li>" in _refusal([A])


class TestTheCheckPanel:

    def test_a_repeated_message_is_one_line_with_its_count(self):
        html = _panel([A, B] * 8)
        assert html.count(A) == 1 and html.count(B) == 1
        assert f"<li>{A} (8 times)</li>" in html

    def test_ten_lines_are_shown_and_every_hidden_error_is_counted(self):
        """A said five times, ten other messages, then one said twice: twelve
        lines. Ten are listed (A and Problem 0-8); the two hidden lines,
        Problem 9 and Eleven, are three errors."""
        lines = [A] * 5 + [f"Problem {k}." for k in range(10)] + ["Eleven."] * 2
        html = _panel(lines)
        assert f"<li>{A} (5 times)</li>" in html
        assert "Problem 8." in html and "Problem 9." not in html and "Eleven." not in html
        assert "and 3 more on the validation page." in html

    def test_no_count_line_when_every_message_is_shown(self):
        assert "more on the validation page" not in _panel([A, B] * 8)
