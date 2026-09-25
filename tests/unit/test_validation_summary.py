"""validation_summary: every blocking error as a sentence, and per sample.

The Mark-Ready refusal lists error_messages(); the run page marks the rows
errors_by_sample() names. Both must agree with ValidationResult.error_count
and never change the run.
"""

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.validation import ValidationService, clear_validation_cache
from seqsetup.services.validation_summary import error_messages, errors_by_sample


def _pair(n, i7, i5):
    return IndexPair(
        id=f"p{n}", name=f"P{n}",
        index1=Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5),
    )


def _run():
    """A and B collide in lane 1; two samples share the ID DUP; LANE9 is on
    a lane the flowcell does not have; OK is clean."""
    run = SequencingRun(
        run_name="Summary run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(Sample(id="a", sample_id="A", lanes=[1], index_pair=_pair(1, "ATTACTCG", "TATAGCCT")))
    run.add_sample(Sample(id="b", sample_id="B", lanes=[1], index_pair=_pair(2, "ATTACTCG", "TATAGCCT")))
    run.add_sample(Sample(id="d1", sample_id="DUP", lanes=[2], index_pair=_pair(3, "TCCGGAGA", "ATAGAGGC")))
    run.add_sample(Sample(id="d2", sample_id="DUP", lanes=[3], index_pair=_pair(4, "CGCTCATT", "CCTATCCT")))
    run.add_sample(Sample(id="l9", sample_id="LANE9", lanes=[9], index_pair=_pair(5, "GAGATTCC", "GGCTCTGA")))
    run.add_sample(Sample(id="ok", sample_id="OK", lanes=[4], index_pair=_pair(6, "ATTCAGAA", "AGGCGAAG")))
    return run


def _result(run):
    clear_validation_cache()
    return ValidationService.validate_run(run)


class TestErrorMessages:
    """error_messages lists each blocking error once, as the PDF does."""

    def test_one_message_per_error(self):
        run = _run()
        result = _result(run)
        assert result.error_count > 0
        assert len(error_messages(result)) == result.error_count

    def test_names_the_problems(self):
        text = "\n".join(error_messages(_result(_run())))
        assert "DUP" in text
        assert "lane 9" in text
        assert "A (ATTACTCG)" in text or "A " in text

    def test_clean_run_has_none(self):
        run = SequencingRun(run_name="Clean", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                            flowcell_type="10B", run_cycles=RunCycles(151, 151, 8, 8))
        run.add_sample(Sample(id="ok", sample_id="OK", lanes=[1], index_pair=_pair(1, "ATTACTCG", "TATAGCCT")))
        assert error_messages(_result(run)) == []


class TestErrorsBySample:
    """errors_by_sample marks exactly the samples an error names."""

    def test_collision_marks_both_samples(self):
        run = _run()
        by_id = errors_by_sample(run, _result(run))
        assert any("collision" in m for m in by_id["a"])
        assert any("collision" in m for m in by_id["b"])

    def test_duplicate_id_marks_every_copy(self):
        run = _run()
        by_id = errors_by_sample(run, _result(run))
        assert any("DUP" in m for m in by_id["d1"])
        assert any("DUP" in m for m in by_id["d2"])

    def test_configuration_error_found_by_display_name(self):
        run = _run()
        by_id = errors_by_sample(run, _result(run))
        assert any("lane 9" in m for m in by_id["l9"])

    def test_clean_sample_not_marked(self):
        run = _run()
        assert "ok" not in errors_by_sample(run, _result(run))

    def test_does_not_change_the_run(self):
        run = _run()
        before = run.to_dict()
        errors_by_sample(run, _result(run))
        assert run.to_dict() == before
