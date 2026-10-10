"""Seven Mark Ready rules no test checked: switched off one at a time, the
whole suite still passed (2026-10-03 project review, H-1; spec 2026-10-05
group A3, §5). Each test here makes its rule fire."""

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.models.validation import ValidationSeverity
from seqsetup.services.validation import ValidationService, clear_validation_cache

from .test_sheet_plan import _app, _dragen, _repos, _test

RC = RunCycles(151, 151, 10, 10)


def _sample(sample_id, i7, i5=None, test="WGS") -> Sample:
    sample = Sample(sample_id=sample_id, test_id=test, test_version="1" if test else "", lanes=[1])
    if i5 is None:
        sample.assign_index1(Index(name=f"{sample_id}7", sequence=i7, index_type=IndexType.I7))
    else:
        sample.index_pair = IndexPair(
            id=f"p{sample_id}", name=f"p{sample_id}",
            index1=Index(name=f"{sample_id}7", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"{sample_id}5", sequence=i5, index_type=IndexType.I5))
    return sample


def _run(*samples) -> SequencingRun:
    return SequencingRun(run_name="Rules", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                         flowcell_type="10B", run_cycles=RC, samples=list(samples))


def _configuration(run, category):
    return [e for e in ValidationService.validate_configuration(run) if e.category == category]


class TestTheIndexLengthChecks:
    """All samples in a lane read the same number of index cycles."""

    def test_the_i7(self):
        run = _run(_sample("A", "ACGTACGT", "TTGGCCAATT"), _sample("B", "TGCATGCAAC", "CCAATTGGTT"))
        (error,) = _configuration(run, "index_length_mismatch")
        assert error.severity == ValidationSeverity.ERROR
        assert error.message == (
            "Lane 1: i7 index lengths are inconsistent - 8bp (1 samples), 10bp (1 samples). "
            "All samples in a lane must have the same index length.")

    def test_the_i5(self):
        run = _run(_sample("A", "ACGTACGTAC", "TTGGCCAA"), _sample("B", "TGCATGCAAC", "CCAATTGGTT"))
        (error,) = _configuration(run, "index_length_mismatch")
        assert error.message.startswith("Lane 1: i5 index lengths are inconsistent - 8bp")


class TestMixedIndexing:
    def test_single_and_dual_in_one_lane(self):
        run = _run(_sample("A", "ACGTACGTAC", "TTGGCCAATT"), _sample("B", "TGCATGCAAC"))
        (error,) = _configuration(run, "mixed_indexing")
        assert error.severity == ValidationSeverity.ERROR
        assert error.message == (
            "Lane 1: mixed single-indexed (1 samples) and dual-indexed (1 samples). All samples "
            "in a lane must use the same indexing mode.")


def _application_errors(run, apps, tests) -> list:
    test_repo, app_repo = _repos(apps, tests)
    clear_validation_cache()
    return ValidationService.validate_run(run, test_profile_repo=test_repo,
                                          app_profile_repo=app_repo).application_errors


class TestTheApplicationChecks:
    """The instrument offers each application, in the version the profile
    names, and one version per application across the run."""

    def test_an_application_the_instrument_does_not_have(self):
        apps = [_app("BCLX"), _dragen("FooX", "DragenFoo")]
        tests = [_test("WGS", ("BCLX", "1.0.0"), ("FooX", "1.0.0"))]
        errors = _application_errors(_run(_sample("S1", "ACGTACGTAC", "TTGGCCAATT")), apps, tests)
        assert [(e.error_type, e.detail) for e in errors] == [(
            "app_not_available",
            "Application 'DragenFoo' (from profile 'FooX') is not available on NovaSeq X Series")]

    def test_a_version_the_instrument_does_not_have(self):
        apps = [_app("BCLX", settings={"SoftwareVersion": "9.9.9"}), _dragen("GermX")]
        tests = [_test("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0"))]
        errors = _application_errors(_run(_sample("S1", "ACGTACGTAC", "TTGGCCAATT")), apps, tests)
        assert [(e.error_type, e.detail) for e in errors] == [(
            "version_not_available",
            "Application 'BCLConvert' version '9.9.9' (from profile 'BCLX') is not available on "
            "NovaSeq X Series. Available: 4.3.6")]

    def test_two_versions_of_one_application(self):
        apps = [_app("BCLX"), _app("BCLY", settings={"SoftwareVersion": "9.9.9"})]
        tests = [_test("WGS", ("BCLX", "1.0.0")), _test("PANEL", ("BCLY", "1.0.0"))]
        run = _run(_sample("S1", "ACGTACGTAC", "TTGGCCAATT"),
                   _sample("S2", "TGCATGCAAC", "CCAATTGGTT", test="PANEL"))
        conflicts = [e for e in _application_errors(run, apps, tests)
                     if e.error_type == "version_conflict"]
        assert [e.detail for e in conflicts] == [
            "Application 'BCLConvert' requires multiple versions across samples: 4.3.6 (from "
            "BCLX), 9.9.9 (from BCLY). All samples in a run must use the same version."]


class TestTheI7DarkStart:
    """On a two-colour instrument an i7 whose first two bases are dark stops
    Mark Ready (A2's tests cover the i5)."""

    def test_an_i7_starting_gg(self):
        clear_validation_cache()
        result = ValidationService.validate_run(_run(_sample("S1", "GGTACGTACG", "TTGGCCAATT")))
        assert [(e.sample_name, e.index_type, e.sequence) for e in result.dark_cycle_errors] == [
            ("S1", "i7", "GGTACGTACG")]
        assert result.error_count >= 1
