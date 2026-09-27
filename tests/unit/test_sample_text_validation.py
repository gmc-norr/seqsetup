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
