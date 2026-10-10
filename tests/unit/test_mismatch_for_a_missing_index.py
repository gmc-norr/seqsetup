"""A mismatch number for an index the sample does not have: DRAGEN 4.3 and 4.4
want the cell "blank or 'na'", and a Settings value only when every sample
has that index (spec 2026-10-10 later list slice 1, §3)."""

from seqsetup.models.sample import Sample
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter

from .test_sheet_plan import _app, _dragen, _plan, _problems, _repos, _run, _sample, _test, _wgs


def _data(run, apps, tests):
    test_repo, app_repo = _repos(apps, tests)
    sheet = SampleSheetV2Exporter.export(run, test_repo, app_repo)
    return sheet.split("[BCLConvert_Data]\n", 1)[1].split("\n\n", 1)[0].splitlines()


def _no_index(sample_id):
    return Sample(sample_id=sample_id, test_id="WGS", test_version="1", lanes=[1])


class TestASampleWithoutTheIndexGetsNa:

    def test_a_single_index_sample_in_a_dual_index_run(self):
        apps, tests = _wgs()
        rows = _data(_run(_sample("S1"), _sample("S2", i5=None)), apps, tests)
        assert rows[1:] == ["S1,1,ACGTACGTAC,TTGGCCAATT,Y151;I10;I10;Y151,1,1",
                            "S2,1,ACGTACGTAC,,Y151;I10;N10;Y151,1,na"]

    def test_a_sample_with_no_index(self):
        apps, tests = _wgs()
        rows = _data(_run(_sample("S1"), _no_index("S3")), apps, tests)
        assert rows[2] == "S3,1,,,,na,na"

    def test_the_samples_own_number_does_not_apply(self):
        apps, tests = _wgs()
        single = _sample("S2", i5=None)
        single.barcode_mismatches_index1 = 0
        single.barcode_mismatches_index2 = 2
        rows = _data(_run(_sample("S1"), single), apps, tests)
        assert rows[2] == "S2,1,ACGTACGTAC,,Y151;I10;N10;Y151,0,na"

    def test_the_profiles_default_does_not_apply(self):
        apps = [_app("BCLX", data={"BarcodeMismatchesIndex1": 2, "BarcodeMismatchesIndex2": 2}),
                _dragen("GermX")]
        tests = [_test("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0"))]
        dual, single = _sample("S1"), _sample("S2", i5=None)
        for sample in (dual, single):
            sample.barcode_mismatches_index1 = sample.barcode_mismatches_index2 = None
        rows = _data(_run(dual, single), apps, tests)
        assert [r.rsplit(",", 2)[1:] for r in rows[1:]] == [["2", "2"], ["2", "na"]]


def _settings_profile(**settings):
    fields = ["Sample_ID", "Lane", "Index", "Index2", "OverrideCycles"]
    apps = [_app("BCLX", settings={"SoftwareVersion": "4.3.6", **settings}, data={}, fields=fields),
            _dragen("GermX")]
    return apps, [_test("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0"))]


def _message(column, n, index, ids):
    return (f"BCLConvert profile BCLX 1.0.0 sets {column} for the whole run in its Settings, but "
            f"{n} sample(s) have no {index}: {ids}. DRAGEN takes {column} in Settings only when "
            f"every sample has that index. Move {column} from the profile's Settings to its "
            f"DataFields, or put these samples in another run.")


class TestAMismatchSettingNeedsTheIndexInEverySample:

    def test_index2_with_a_single_index_sample(self):
        apps, tests = _settings_profile(BarcodeMismatchesIndex2=1)
        plan = _plan(_run(_sample("S1"), _sample("S2", i5=None), _sample("S3", i5=None)),
                     apps, tests)
        [problem] = _problems(plan, "mismatch_setting_without_index")
        assert problem.message == _message("BarcodeMismatchesIndex2", 2, "i5", "S2, S3")
        assert problem.sample_names == ("S2", "S3")

    def test_index1_with_a_sample_without_an_index(self):
        apps, tests = _settings_profile(BarcodeMismatchesIndex1=0)
        plan = _plan(_run(_sample("S1"), _no_index("S3")), apps, tests)
        [problem] = _problems(plan, "mismatch_setting_without_index")
        assert problem.message == _message("BarcodeMismatchesIndex1", 1, "i7", "S3")

    def test_both_columns_give_two_problems(self):
        apps, tests = _settings_profile(BarcodeMismatchesIndex1=1, BarcodeMismatchesIndex2=1)
        plan = _plan(_run(_sample("S1"), _no_index("S3")), apps, tests)
        assert [p.message for p in _problems(plan, "mismatch_setting_without_index")] == [
            _message("BarcodeMismatchesIndex1", 1, "i7", "S3"),
            _message("BarcodeMismatchesIndex2", 1, "i5", "S3"),
        ]

    def test_none_when_every_sample_has_the_index(self):
        apps, tests = _settings_profile(BarcodeMismatchesIndex1=1, BarcodeMismatchesIndex2=1)
        plan = _plan(_run(_sample("S1"), _sample("S2", i7="TGCATGCAAC", i5="CCAATTGGTT")),
                     apps, tests)
        assert _problems(plan, "mismatch_setting_without_index") == []

    def test_none_without_the_setting(self):
        apps, tests = _settings_profile()
        plan = _plan(_run(_sample("S1"), _sample("S2", i5=None)), apps, tests)
        assert _problems(plan, "mismatch_setting_without_index") == []
