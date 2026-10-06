"""Mark Ready's checks use the sheet plan (spec 2026-10-05 group A3, §1, §2):
its problems are errors, its warning is a warning, the collision checks use
the mismatch numbers the sheet gives BCL Convert, and the result carries the
plan's fingerprint."""

from seqsetup.models.validation import ValidationSeverity
from seqsetup.services.validation import ValidationService, clear_validation_cache

from .test_sheet_plan import BCL_FIELDS, _app, _dragen, _repos, _run, _sample, _test, _wgs


def _validate(run, apps, tests):
    test_repo, app_repo = _repos(apps, tests)
    clear_validation_cache()
    return ValidationService.validate_run(run, test_profile_repo=test_repo,
                                          app_profile_repo=app_repo)


def _of(result, category):
    return [e for e in result.configuration_errors if e.category == category]


def _pair(i7_b="ACGTACGGGG", **fields):
    """Two single-index samples whose i7s differ in 3 bases."""
    a = _sample("A", i7="ACGTACGTAC", i5=None, **fields)
    b = _sample("B", i7=i7_b, i5=None, **fields)
    return a, b


class TestThePlansProblemsAreErrors:
    def test_a_test_without_a_bclconvert_profile(self):
        apps = [_dragen("GermX")]
        tests = [_test("DRAGEN_ONLY", ("GermX", "1.0.0"))]
        result = _validate(_run(_sample("S1", "DRAGEN_ONLY")), apps, tests)
        (error,) = _of(result, "test_without_bclconvert_profile")
        assert error.severity == ValidationSeverity.ERROR
        assert error.sample_names == ["S1"]
        assert result.error_count >= 1

    def test_lanes_not_picked(self):
        result = _validate(_run(_sample("S1", lanes=())), *_wgs())
        assert [e.severity for e in _of(result, "lanes_not_picked")] == [ValidationSeverity.ERROR]

    def test_the_writers_own_problems_are_not_reported_twice(self):
        apps, _tests = _wgs()
        result = _validate(_run(_sample("S1")), apps, [])
        assert [e.error_type for e in result.application_errors] == ["test_profile_not_found"]
        assert [e for e in result.configuration_errors if not e.category] == []

    def test_a_run_without_problems_gets_none(self):
        result = _validate(_run(_sample("S1")), *_wgs())
        plan_categories = {"test_without_bclconvert_profile", "lanes_not_picked",
                           "bclconvert_column_missing", "mismatch_number_not_in_sheet"}
        assert [e for e in result.configuration_errors if e.category in plan_categories] == []


class TestTheMismatchNumbersTheChecksUse:
    """The checks use the number the sheet gives BCL Convert (spec §2)."""

    def test_a_data_default_of_2_makes_a_distance_3_pair_collide(self):
        profile = _app("BCLX", data={"BarcodeMismatchesIndex1": 2, "BarcodeMismatchesIndex2": 1})
        a, b = _pair()
        a.barcode_mismatches_index1 = b.barcode_mismatches_index1 = None
        result = _validate(_run(a, b), [profile, _dragen("GermX")], _wgs()[1])
        assert [(c.hamming_distance, c.mismatch_threshold) for c in result.index_collisions] == [
            (3, 4)]

    def test_the_run_number_is_not_used_on_the_profile_path(self):
        profile = _app("BCLX", data={"BarcodeMismatchesIndex1": 2, "BarcodeMismatchesIndex2": 1})
        a, b = _pair()
        a.barcode_mismatches_index1 = b.barcode_mismatches_index1 = None
        run = _run(a, b)
        assert run.barcode_mismatches_index1 == 1
        assert len(_validate(run, [profile, _dragen("GermX")], _wgs()[1]).index_collisions) == 1

    def test_a_settings_only_profile_with_0_checks_at_0_and_warns(self):
        profile = _app("BCLX", settings={"SoftwareVersion": "4.3.6",
                                         "BarcodeMismatchesIndex1": 0,
                                         "BarcodeMismatchesIndex2": 0},
                       fields=BCL_FIELDS[:5], data={})
        a, b = _pair(i7_b="ACGTACGTAA")   # distance 1: collides at 1, not at 0
        result = _validate(_run(a, b), [profile, _dragen("GermX")], _wgs()[1])
        assert result.index_collisions == []
        (warning,) = _of(result, "mismatch_number_not_in_sheet")
        assert warning.severity == ValidationSeverity.WARNING
        assert warning.sample_names == ["A", "B"]

    def test_the_mismatch_threshold_warning_uses_them(self):
        profile = _app("BCLX", data={"BarcodeMismatchesIndex1": 2, "BarcodeMismatchesIndex2": 1})
        a, b = _pair(i7_b="ACGTAGGGGG")   # distance 4: at 2x the sheet's number 2
        a.barcode_mismatches_index1 = b.barcode_mismatches_index1 = None
        result = _validate(_run(a, b), [profile, _dragen("GermX")], _wgs()[1])
        (warning,) = _of(result, "mismatch_threshold_risk")
        assert "2x the barcode mismatch threshold (2)" in warning.message

    def test_without_the_repositories_todays_numbers(self):
        a, b = _pair()
        a.barcode_mismatches_index1 = b.barcode_mismatches_index1 = None
        clear_validation_cache()
        assert ValidationService.validate_run(_run(a, b)).index_collisions == []


class TestTheFingerprint:
    def test_the_result_carries_the_plans_fingerprint(self):
        from seqsetup.services.sheet_plan import plan_sheet
        run = _run(_sample("S1"))
        apps, tests = _wgs()
        test_repo, app_repo = _repos(apps, tests)
        clear_validation_cache()
        result = ValidationService.validate_run(run, test_profile_repo=test_repo,
                                                app_profile_repo=app_repo)
        assert result.sheet_plan_fingerprint == plan_sheet(run, test_repo, app_repo, 8).fingerprint
        assert result.sheet_plan_fingerprint

    def test_none_without_the_repositories(self):
        clear_validation_cache()
        assert ValidationService.validate_run(_run(_sample("S1"))).sheet_plan_fingerprint == ""
