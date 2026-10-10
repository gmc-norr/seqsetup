"""No lane splitting with a Lane column: DRAGEN 4.3 "only supports this mode
when no 'Lane' column is specified in the sample sheet" (spec 2026-10-10
later list slice 1, §3)."""

import pytest

from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter
from seqsetup.services.sheet_plan import SheetPlanProblem

from .test_sheet_plan import BCL_FIELDS, _app, _dragen, _plan, _problems, _repos, _run, _sample, _test, _wgs

ALL_LANES = tuple(range(1, 9))


def _message(where):
    return (f"BCLConvert profile BCLX 1.0.0 has a Lane column, and NoLaneSplitting is true "
            f"({where}). DRAGEN 4.3 converts a run without lane splitting only when the Sample "
            f"Sheet has no Lane column. Set NoLaneSplitting to false, or use a BCLConvert profile "
            f"without a Lane column.")


def _setting(value, fields=BCL_FIELDS):
    apps = [_app("BCLX", settings={"SoftwareVersion": "4.3.6", "NoLaneSplitting": value},
                 fields=fields), _dragen("GermX")]
    return apps, [_test("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0"))]


class TestNoLaneSplittingNeedsASheetWithoutALaneColumn:

    def test_the_runs_setting(self):
        apps, tests = _wgs()
        plan = _plan(_run(_sample("S1"), no_lane_splitting=True), apps, tests)
        [problem] = _problems(plan, "no_lane_splitting_with_lane")
        assert problem.message == _message("the run's setting")

    @pytest.mark.parametrize("value", [True, "true", "TRUE", 1, "1"],
                             ids=["True", "true", "TRUE", "int-1", "text-1"])
    def test_the_profiles_setting(self, value):
        apps, tests = _setting(value)
        plan = _plan(_run(_sample("S1")), apps, tests)
        [problem] = _problems(plan, "no_lane_splitting_with_lane")
        assert problem.message == _message("in the profile's Settings")

    @pytest.mark.parametrize("value", [False, "false", "False", 0, "0"],
                             ids=["False", "false", "text-False", "int-0", "text-0"])
    def test_the_profiles_false_wins_over_the_run(self, value):
        apps, tests = _setting(value)
        plan = _plan(_run(_sample("S1"), no_lane_splitting=True), apps, tests)
        assert _problems(plan, "no_lane_splitting_with_lane") == []

    def test_none_without_a_lane_column(self):
        apps, tests = _setting(True, fields=[f for f in BCL_FIELDS if f != "Lane"])
        plan = _plan(_run(_sample("S1", lanes=ALL_LANES)), apps, tests)
        assert plan.problems == []

    def test_none_when_lanes_are_split_as_today(self):
        apps, tests = _wgs()
        plan = _plan(_run(_sample("S1")), apps, tests)
        assert _problems(plan, "no_lane_splitting_with_lane") == []

    def test_the_writer_refuses_it(self):
        apps, tests = _wgs()
        test_repo, app_repo = _repos(apps, tests)
        with pytest.raises(SheetPlanProblem, match="NoLaneSplitting is true"):
            SampleSheetV2Exporter.export(_run(_sample("S1"), no_lane_splitting=True),
                                         test_repo, app_repo)
