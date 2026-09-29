"""Line breaks in sample text must block Mark Ready.

The Sample Sheet is a line-based file. A line break inside a sample ID,
sample name, project or description starts a new line in the sheet, and a
line-based reader then sees a broken row, or a row (even a whole section)
that nobody entered.
"""

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from seqsetup.services.validation import ValidationService


def _run_with(sample: Sample) -> SequencingRun:
    sample.index_pair = IndexPair(
        id="p1", name="p1",
        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
    )
    run = SequencingRun(
        run_name="Run1",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(sample)
    return run


def _errors(run: SequencingRun, category: str) -> list:
    return [
        e for e in ValidationService.validate_configuration(run)
        if e.category == category
    ]


class TestSampleIdLineBreak:
    """A sample ID may hold only letters, digits, '-' and '_' — a line break
    at the very end included."""

    def test_trailing_newline_in_sample_id_is_an_error(self):
        run = _run_with(Sample(sample_id="S1\n"))

        errors = _errors(run, "invalid_sample_id")

        assert len(errors) == 1
        assert errors[0].severity.value == "error"
        assert "'\\n'" in errors[0].message

    def test_sample_id_clamped_to_end_in_newline_is_an_error(self):
        # What a route stores for 255 letters, a newline and more text:
        # sanitize_string strips the ends first, then cuts at 256.
        run = _run_with(Sample(sample_id="A" * 255 + "\n"))

        assert len(_errors(run, "invalid_sample_id")) == 1

    def test_valid_sample_id_is_accepted(self):
        run = _run_with(Sample(sample_id="S1-a_B2"))

        assert _errors(run, "invalid_sample_id") == []


LINE_BREAKS = [
    pytest.param("\n", id="LF"),
    pytest.param("\r", id="CR"),
    pytest.param("\r\n", id="CRLF"),
    pytest.param("\x0b", id="VT"),
    pytest.param("\x0c", id="FF"),
    pytest.param("\x85", id="NEL"),
    pytest.param("\u2028", id="LINE-SEPARATOR"),
    pytest.param("\u2029", id="PARAGRAPH-SEPARATOR"),
]

TEXT_FIELDS = [
    pytest.param("sample_name", "sample name", id="sample_name"),
    pytest.param("project", "project", id="project"),
    pytest.param("description", "description", id="description"),
]


class TestSampleTextLineBreaks:
    """Sample name, project and description are free text, but a line break
    in any of them is an error."""

    @pytest.mark.parametrize("attr,label", TEXT_FIELDS)
    @pytest.mark.parametrize("line_break", LINE_BREAKS)
    def test_line_break_in_sample_text_is_an_error(self, attr, label, line_break):
        sample = Sample(sample_id="S1")
        setattr(sample, attr, f"first{line_break}second")
        run = _run_with(sample)

        errors = _errors(run, "line_break_in_sample_text")

        assert len(errors) == 1
        assert errors[0].severity.value == "error"
        assert label in errors[0].message
        assert errors[0].sample_names == ["S1"]

    @pytest.mark.parametrize("attr,label", TEXT_FIELDS)
    def test_trailing_line_break_is_an_error(self, attr, label):
        sample = Sample(sample_id="S1")
        setattr(sample, attr, "text\n")

        assert len(_errors(_run_with(sample), "line_break_in_sample_text")) == 1

    def test_all_fields_with_line_breaks_give_one_error_naming_each(self):
        sample = Sample(
            sample_id="S1",
            sample_name="a\nb",
            project="c\nd",
            description="e\nf",
        )

        errors = _errors(_run_with(sample), "line_break_in_sample_text")

        assert len(errors) == 1
        for label in ("sample name", "project", "description"):
            assert label in errors[0].message

    def test_plain_text_is_accepted(self):
        sample = Sample(
            sample_id="S1",
            sample_name="Tube 2, rack A",
            project="Project \"X\"; batch 7",
            description="Tab\there is fine",
        )

        assert _errors(_run_with(sample), "line_break_in_sample_text") == []

    def test_empty_text_is_accepted(self):
        assert _errors(_run_with(Sample(sample_id="S1")), "line_break_in_sample_text") == []

    def test_each_bad_sample_gets_its_own_error(self):
        run = _run_with(Sample(sample_id="S1", sample_name="a\nb"))
        run.add_sample(Sample(sample_id="S2", project="c\rd"))
        run.add_sample(Sample(sample_id="S3", sample_name="fine"))

        errors = _errors(run, "line_break_in_sample_text")

        assert sorted(e.sample_names[0] for e in errors) == ["S1", "S2"]


HIDDEN = [
    pytest.param("\x00", "U+0000", id="NUL"),
    pytest.param("\t", "U+0009 (tab)", id="TAB"),
    pytest.param("\x1f", "U+001F", id="US"),
    pytest.param("\x7f", "U+007F", id="DEL"),
    pytest.param("\x9b", "U+009B", id="C1-CSI"),
]


class TestSampleTextHiddenCharacters:
    """A hidden character other than a line break in a sample's name, project
    or description is its own Mark Ready error (audit 2026-09 N-12)."""

    @pytest.mark.parametrize("attr,label", TEXT_FIELDS)
    @pytest.mark.parametrize("char,code", HIDDEN)
    def test_hidden_character_in_sample_text_is_an_error(self, attr, label, char, code):
        sample = Sample(sample_id="S1")
        setattr(sample, attr, f"A{char}B")

        errors = _errors(_run_with(sample), "hidden_character_in_text")

        assert len(errors) == 1
        assert errors[0].severity.value == "error"
        assert errors[0].sample_names == ["S1"]
        assert errors[0].message.startswith(
            f"Sample 'S1' has a hidden character in its {label}: {code}."
        )
        assert "Remove it before marking the run ready." in errors[0].message

    @pytest.mark.parametrize(
        "line_break",
        sorted(ValidationService._LINE_BREAK_CHARS),
        ids=lambda c: f"U+{ord(c):04X}",
    )
    def test_line_break_alone_gives_only_the_line_break_error(self, line_break):
        run = _run_with(Sample(sample_id="S1", sample_name=f"A{line_break}B"))

        assert len(_errors(run, "line_break_in_sample_text")) == 1
        assert _errors(run, "hidden_character_in_text") == []

    def test_line_break_and_nul_give_each_error_once(self):
        run = _run_with(Sample(sample_id="S1", project="A\nB\x00C"))

        assert len(_errors(run, "line_break_in_sample_text")) == 1
        hidden = _errors(run, "hidden_character_in_text")
        assert len(hidden) == 1
        assert "U+0000" in hidden[0].message
        assert "U+000A" not in hidden[0].message

    def test_several_fields_and_characters_make_one_error(self):
        sample = Sample(sample_id="S1", project="P\x00", description="D\tE")

        errors = _errors(_run_with(sample), "hidden_character_in_text")

        assert len(errors) == 1
        assert (
            "has hidden characters in its project and description: U+0000, U+0009 (tab)."
            in errors[0].message
        )
        assert "Remove them before marking the run ready." in errors[0].message

    def test_visible_text_in_any_script_is_accepted(self):
        sample = Sample(
            sample_id="S1", sample_name="Åsa Öberg", project="Проект-7",
            description="试验 2, rack A",
        )

        assert _errors(_run_with(sample), "hidden_character_in_text") == []


RUN_TEXT_FIELDS = [
    pytest.param("run_name", "name", id="run_name"),
    pytest.param("run_description", "description", id="run_description"),
]


class TestRunTextHiddenCharacters:
    """The run's name and description are checked for every hidden character
    (audit 2026-09 N-12)."""

    @pytest.mark.parametrize("attr,label", RUN_TEXT_FIELDS)
    @pytest.mark.parametrize("char,code", HIDDEN + [
        pytest.param("\x0b", "U+000B", id="VT"),
        pytest.param("\u2028", "U+2028", id="LINE-SEPARATOR"),
    ])
    def test_hidden_character_in_run_text_is_an_error(self, attr, label, char, code):
        run = _run_with(Sample(sample_id="S1"))
        setattr(run, attr, f"Run{char}1")

        errors = _errors(run, "hidden_character_in_text")

        assert len(errors) == 1
        assert errors[0].severity.value == "error"
        assert errors[0].message.startswith(
            f"The run has a hidden character in its {label}: {code}."
        )

    def test_run_without_samples_is_still_checked(self):
        run = SequencingRun(run_name="Run1", run_description="a\tb")

        assert len(_errors(run, "hidden_character_in_text")) == 1

    def test_line_break_in_description_is_saved_as_a_space(self):
        run = SequencingRun(run_name="Run1", run_description="line one\nline two")

        assert run.run_description == "line one line two"
        assert _errors(run, "hidden_character_in_text") == []

    def test_visible_run_text_is_accepted(self):
        run = _run_with(Sample(sample_id="S1"))
        run.run_description = "Åsa's run, 2 × 150"

        assert _errors(run, "hidden_character_in_text") == []


class TestInvisibleCharactersInText:
    """A zero-width space or another invisible format character is a hidden
    character too, and the message says how to remove what cannot be seen
    (spec 2026-09-29 Sample Sheet follow-ups, §3)."""

    def test_zero_width_space_in_sample_name_is_an_error(self):
        run = _run_with(Sample(sample_id="S1", sample_name="A​B"))

        errors = _errors(run, "hidden_character_in_text")

        assert [e.message for e in errors] == [
            "Sample 'S1' has a hidden character in its sample name: U+200B. Hidden "
            "characters can break the Sample Sheet. Remove it before marking the run "
            "ready. If you cannot see it, delete the text and type it again."
        ]

    def test_several_characters_are_called_them(self):
        run = _run_with(Sample(sample_id="S1", project="P​﻿"))

        errors = _errors(run, "hidden_character_in_text")

        assert len(errors) == 1
        assert errors[0].message.endswith(
            "Remove them before marking the run ready. If you cannot see them, "
            "delete the text and type it again."
        )

    def test_direction_override_in_run_name_is_an_error(self):
        run = _run_with(Sample(sample_id="S1"))
        run.run_name = "Run‮1"

        errors = _errors(run, "hidden_character_in_text")

        assert len(errors) == 1
        assert errors[0].message.startswith(
            "The run has a hidden character in its name: U+202E."
        )
