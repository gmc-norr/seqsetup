"""Tests for prerequisite ConfigurationError entries in ValidationService."""

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, SequencingRun
from seqsetup.services.validation import ValidationService


class TestValidationPrerequisites:
    """ValidationService surfaces prerequisite failures as configuration errors."""

    def test_validate_configuration_flags_empty_run_as_error(self):
        """An empty run gets a prerequisite_no_samples error with error_count >= 1."""
        run = SequencingRun(instrument_platform=InstrumentPlatform.NOVASEQ_X)
        result = ValidationService.validate_run(run)
        categories = [e.category for e in result.configuration_errors]
        assert "prerequisite_no_samples" in categories
        assert result.error_count >= 1

    def test_validate_configuration_flags_missing_indexes_as_error(self):
        """Samples without indexes get a prerequisite_missing_indexes error."""
        run = SequencingRun(instrument_platform=InstrumentPlatform.NOVASEQ_X)
        run.add_sample(Sample(sample_id="S1", test_id="WGS", lanes=[1]))
        run.add_sample(Sample(sample_id="S2", test_id="WGS", lanes=[1]))
        result = ValidationService.validate_run(run)
        categories = [e.category for e in result.configuration_errors]
        assert "prerequisite_missing_indexes" in categories
        missing_err = next(
            e for e in result.configuration_errors
            if e.category == "prerequisite_missing_indexes"
        )
        assert "2 sample(s)" in missing_err.message
        assert "S1" in missing_err.message
        assert "S2" in missing_err.message
