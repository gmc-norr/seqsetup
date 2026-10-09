"""The sheet plan and the checks find each sample's test profile from its test
and version (spec 2026-10-07 group A4, §3)."""

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.test_profile import TestProfile as _TestProfile
from seqsetup.services.sheet_plan import plan_sheet
from seqsetup.services.validation import ValidationService

import pytest

from .test_sheet_plan import _app, _repos, _run


def _sample(sample_id, test="WGS", i7="ACGTACGTAC", i5="TTGGCCAATT", version="1") -> Sample:
    """An indexed sample on lane 1 asking for ``test`` at ``version``."""
    sample = Sample(sample_id=sample_id, test_id=test, test_version=version, lanes=[1])
    sample.index_pair = IndexPair(
        id=f"p{sample_id}", name=f"p{sample_id}",
        index1=Index(name=f"{sample_id}7", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"{sample_id}5", sequence=i5, index_type=IndexType.I5),
    )
    return sample


def _test(version, bcl_version="1.0.0", test="WGS"):
    return _TestProfile.from_yaml({
        "TestType": test, "TestName": test, "Description": test, "Version": version,
        "ApplicationProfiles": [{"ApplicationProfileName": "BCLX",
                                 "ApplicationProfileVersion": bcl_version}],
    }, f"{test}_{version}.yaml")


def _bcl(version, mismatch=1):
    return _app("BCLX", version=version,
                data={"BarcodeMismatchesIndex1": mismatch, "BarcodeMismatchesIndex2": 1})


def _plan(run, apps, tests):
    return plan_sheet(run, *_repos(apps, tests), 8)


class TestTheWritersOwnTexts:
    def test_a_sample_without_a_version(self):
        plan = _plan(_run(_sample("S1", version="")), [_bcl("1.0.0")], [_test("1.0.0")])
        assert [p.message for p in plan.problems] == [
            "Sample S1 has no test version, so it would not be on the Sample Sheet."]
        assert plan.sections == []

    def test_a_version_no_file_matches(self):
        plan = _plan(_run(_sample("S1", version="2")), [_bcl("1.0.0")], [_test("1.0.0")])
        assert [p.message for p in plan.problems] == ["Test 'WGS' 2 has no test profile."]

    def test_two_versions_of_one_test_are_told_apart(self):
        # Before: "BCLX 1.0.0 (test WGS) and BCLX 2.0.0 (test WGS)".
        apps = [_bcl("1.0.0"), _app("BCLX", version="2.0.0",
                                    settings={"SoftwareVersion": "4.3.6", "FastqCompressionFormat": "gzip"})]
        tests = [_test("1.0.0"), _test("2.0.0", bcl_version="2.0.0")]
        run = _run(_sample("S1", version="1"),
                   _sample("S2", i7="TTTTGGGGCC", i5="GGCCTTAAGG", version="2"))
        assert [p.message for p in _plan(run, apps, tests).problems] == [
            "BCLConvert: profiles BCLX 1.0.0 (test WGS 1) and BCLX 2.0.0 (test WGS 2) have "
            "different Settings, and a Sample Sheet has one [BCLConvert_Settings] and one "
            "[BCLConvert_Data] section. Put these tests in separate runs, or give the profiles "
            "the same Settings and columns."]


class TestEachSampleGetsItsOwnVersion:
    def test_two_versions_in_one_run(self):
        # The same BCLConvert columns and Settings, another Data default: one
        # section, each row from its own profile (group A3's rule).
        apps = [_bcl("1.0.0"), _bcl("2.0.0", mismatch=2)]
        tests = [_test("1.0.0"), _test("2.0.0", bcl_version="2.0.0")]
        run = _run(_sample("S1", version="1"),
                   _sample("S2", i7="TTTTGGGGCC", i5="GGCCTTAAGG", version="2"))
        plan = _plan(run, apps, tests)
        assert plan.problems == []
        (section,) = plan.sections
        assert [(s.sample_id, p.version) for s, p in section.rows] == [("S1", "1.0.0"), ("S2", "2.0.0")]

    def test_the_whole_version_text_counts(self):
        # "1.0" asks for the newest 1.0.x, not the newest 1.x.x. 1.1.0 is
        # stored first, so the first stored file is not the answer either.
        apps = [_bcl("1.0.0"), _bcl("2.0.0", mismatch=2)]
        tests = [_test("1.1.0", bcl_version="2.0.0"), _test("1.0.0")]
        plan = _plan(_run(_sample("S1", version="1.0")), apps, tests)
        (section,) = plan.sections
        assert [(s.sample_id, p.version) for s, p in section.rows] == [("S1", "1.0.0")]

    def test_a_newer_match_is_a_change(self):
        run = _run(_sample("S1", version="1"))
        apps = [_bcl("1.0.0")]
        before = _plan(run, apps, [_test("1.0.0")]).fingerprint
        after = _plan(run, apps, [_test("1.0.0"), _test("1.1.0")]).fingerprint
        assert before != after

    def test_a_version_that_does_not_match_is_not_a_change(self):
        run = _run(_sample("S1", version="1"))
        apps = [_bcl("1.0.0")]
        before = _plan(run, apps, [_test("1.0.0")]).fingerprint
        after = _plan(run, apps, [_test("1.0.0"), _test("2.0.0")]).fingerprint
        assert before == after


class TestTheChecks:
    def _result(self, run, tests):
        test_repo, app_repo = _repos([_bcl("1.0.0")], tests)
        return ValidationService.validate_run(run, test_profile_repo=test_repo,
                                              app_profile_repo=app_repo)

    def test_samples_without_a_version(self):
        samples = [_sample(f"S{n}", i7="ACGTACGTAC"[:9] + "ACGT"[n % 4], version="")
                   for n in range(1, 8)]
        result = self._result(_run(*samples), [_test("1.0.0")])
        (error,) = [e for e in result.configuration_errors if e.category == "missing_test_version"]
        assert error.message == (
            "7 sample(s) have a test but no test version: S1, S2, S3, S4, S5 and 2 more. "
            "Set the version on the run page, for example 1.")
        assert error.sample_names == [f"S{n}" for n in range(1, 8)]

    def test_a_sample_without_a_test_is_not_counted_twice(self):
        result = self._result(_run(_sample("S1", test="", version="")), [_test("1.0.0")])
        categories = [e.category for e in result.configuration_errors]
        assert "missing_test_id" in categories
        assert "missing_test_version" not in categories

    @pytest.mark.parametrize("order", [("1", "2"), ("2", "1")])
    def test_each_version_is_checked_on_its_own(self, order):
        # WGS 2.0.0 lists a profile that is not stored: only its sample is named.
        run = _run(_sample("S1", version=order[0]),
                   _sample("S2", i7="TTTTGGGGCC", i5="GGCCTTAAGG", version=order[1]))
        result = self._result(run, [_test("1.0.0"), _test("2.0.0", bcl_version="9.9.9")])
        assert [e.sample_name for e in result.application_errors
                if e.error_type == "profile_not_found"] == [f"S{order.index('2') + 1}"]

    @pytest.mark.parametrize("broken,asked,named", [
        ("1.0.0", "1.0", ["S1"]), ("1.0.0", "1.1", []), ("1.1.0", "1.0", []), ("1.1.0", "1.1", ["S1"])])
    def test_the_whole_version_text_is_resolved(self, broken, asked, named):
        # The broken version lists a profile that is not stored: "1.0" is
        # checked against 1.0.0 and "1.1" against 1.1.0, never the newest
        # 1.x.x (plan review of 562b2e2).
        tests = [_test(v, bcl_version="9.9.9") if v == broken else _test(v) for v in ("1.0.0", "1.1.0")]
        result = self._result(_run(_sample("S1", version=asked)), tests)
        assert [e.sample_name for e in result.application_errors
                if e.error_type == "profile_not_found"] == named

    def test_no_match_is_one_application_error_per_test_and_version(self):
        run = _run(_sample("S1", version="3"),
                   _sample("S2", i7="TTTTGGGGCC", i5="GGCCTTAAGG", version="3"))
        result = self._result(run, [_test("1.0.0")])
        assert [(e.error_type, e.detail) for e in result.application_errors] == [
            ("test_version_not_found",
             "No synced WGS version matches 3. Synced WGS versions: 1.0.0.")]


class TestTheTestsLine:
    def test_the_text(self):
        from seqsetup.services.versioned_tests import versions_used_text
        assert versions_used_text([
            {"test": "WGS", "asked": "1", "version": "1.2.3", "file": "Wgs.yaml"},
            {"test": "RNA", "asked": "2", "version": "2.0.1", "file": ""},
        ]) == "WGS 1 uses 1.2.3 (Wgs.yaml) · RNA 2 uses 2.0.1"

    def test_the_plan_records_what_it_found(self):
        run = _run(_sample("S1", version="1"), _sample("S2", i7="TTTTGGGGCC", i5="GGCCTTAAGG",
                                                       version="1"))
        plan = _plan(run, [_bcl("1.0.0")], [_test("1.0.0"), _test("1.1.0")])
        assert plan.test_versions == [
            {"test": "WGS", "asked": "1", "version": "1.1.0", "file": "WGS_1.1.0.yaml"}]

    def test_a_run_diff_does_not_list_them(self):
        from seqsetup.services.run_diff import diff_run, is_empty
        before = _run(_sample("S1")).to_dict()
        after = dict(before, test_versions_used=[
            {"test": "WGS", "asked": "1", "version": "1.0.0", "file": "WGS_1.0.0.yaml"}])
        assert is_empty(*diff_run(before, after))


class TestTheTestsLineInThePDF:
    """A run with very many tests must still make its report. The Tests line
    is one table cell, and a cell taller than a page is a ReportLab
    LayoutError, which Mark Ready would report as a bare 500."""

    @staticmethod
    def _result(count):
        from seqsetup.models.validation import ValidationResult
        result = ValidationResult(duplicate_sample_ids=[], index_collisions=[],
                                  distance_matrices={})
        result.test_versions = [
            {"test": f"T{i:03d}", "asked": "1", "version": "1.0.0",
             "file": f"T{i:03d}_1.0.0.yaml"}
            for i in range(count)
        ]
        return result

    def test_a_tests_line_taller_than_a_page_still_makes_a_report(self):
        from seqsetup.models.sequencing_run import SequencingRun
        from seqsetup.services.validation_report import ValidationReportPDF
        run = SequencingRun(run_name="Many tests")
        assert ValidationReportPDF.export(run, self._result(400)).startswith(b"%PDF")
