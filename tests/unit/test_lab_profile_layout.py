"""Profiles shared with other tools, and the run's UUID in RunDescription
(docs/design/2026-10-19-lab-profile-layout-design.md).

A test profile lists the instrument's profiles under TestApplicationProfiles >
OnInstrument; DownstreamAnalysis belongs to other tools and is only checked to
be readable. An application profile that is not Dragen is skipped, unless its
ApplicationName is one of Illumina's applications, which is refused. The v2
Sample Sheet writes the run's id as RunDescription, and keeps Custom_UUID."""

import pytest

from seqsetup.input_rules.problems import path_text
from seqsetup.input_rules.profiles import (
    ProfileValidationError,
    check_application_profile_file,
    check_test_profile_file,
)
from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.models.test_profile import TestProfile as _TestProfile
from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter

from .test_sheet_plan import _app, _repos, _test

TEST_YAML = """\
TestType: WGS
TestName: WGSRareDisease
Description: Whole genome
Version: "1.0.0"
TestApplicationProfiles:
  OnInstrument:
    - ApplicationProfileName: BCLConvertNextera
      ApplicationProfileVersion: "~=1.0"
    - ApplicationProfileName: DragenGermlineIdtWgs
      ApplicationProfileVersion: "~=1.0"
  DownstreamAnalysis:
    - ApplicationProfileName: NfCoreRareDisease
      ApplicationProfileVersion: 1
      DependsOn: BCLConvertNextera
"""

PIPELINE_YAML = """\
ApplicationProfileName: NfCoreRareDisease
ApplicationProfileVersion: "1.1"
ApplicationType: nextflow
ApplicationName: nf-core/raredisease
Settings:
  Version: 2.4.0
  Profile: clinical
"""

DRAGEN_YAML = """\
ApplicationProfileName: BCLConvertNextera
ApplicationProfileVersion: 1.0.0
ApplicationName: BCLConvert
ApplicationType: Dragen
Settings:
  SoftwareVersion: 4.3.6
Data:
  BarcodeMismatchesIndex1: 1
DataFields:
  - Sample_ID
  - Index
"""


def _problems(result) -> list[tuple[str, str]]:
    return [(path_text(p.path), p.message) for p in result.problems]


class TestTheTestLayout:
    """OnInstrument is the test's list of application profiles; the rest of
    the file is checked as before."""

    def test_on_instrument_is_the_tests_list(self):
        result = check_test_profile_file(TEST_YAML, "Wgs.yaml")
        assert result.ok, result.problems
        profile = _TestProfile.from_yaml(result.value.model_dump(exclude_unset=True), "Wgs.yaml")
        assert [(r.profile_name, r.profile_version) for r in profile.application_profiles] == [
            ("BCLConvertNextera", "~=1.0"), ("DragenGermlineIdtWgs", "~=1.0")]

    def test_downstream_analysis_is_not_stored(self):
        result = check_test_profile_file(TEST_YAML, "Wgs.yaml")
        profile = _TestProfile.from_yaml(result.value.model_dump(exclude_unset=True), "Wgs.yaml")
        assert "NfCoreRareDisease" not in repr(profile.to_dict())

    def test_downstream_analysis_may_be_left_out(self):
        text = TEST_YAML.split("  DownstreamAnalysis:")[0]
        assert check_test_profile_file(text, "Wgs.yaml").ok

    def test_downstream_analysis_may_be_an_empty_list(self):
        text = TEST_YAML.split("  DownstreamAnalysis:")[0] + "  DownstreamAnalysis: []\n"
        assert check_test_profile_file(text, "Wgs.yaml").ok

    def test_downstream_values_may_be_text_whole_numbers_or_true_false(self):
        text = TEST_YAML + "      Enabled: true\n      Note: any text\n"
        assert check_test_profile_file(text, "Wgs.yaml").ok

    @pytest.mark.parametrize("value", ["[a, b]", "{a: 1}"], ids=["list", "map"])
    def test_a_downstream_value_that_is_not_plain_is_refused(self, value):
        result = check_test_profile_file(TEST_YAML + f"      Extra: {value}\n", "Wgs.yaml")
        assert not result.ok
        assert [place for place, _ in _problems(result)] == [
            "TestApplicationProfiles > DownstreamAnalysis > item 1 > Extra"]

    def test_downstream_analysis_must_be_a_list(self):
        text = TEST_YAML.split("  DownstreamAnalysis:")[0] + "  DownstreamAnalysis: NfCore\n"
        result = check_test_profile_file(text, "Wgs.yaml")
        assert not result.ok
        assert [place for place, _ in _problems(result)] == [
            "TestApplicationProfiles > DownstreamAnalysis"]

    def test_on_instrument_is_required(self):
        text = TEST_YAML.replace("  OnInstrument:\n", "  Elsewhere:\n")
        result = check_test_profile_file(text, "Wgs.yaml")
        assert ("TestApplicationProfiles > OnInstrument", "is required") in _problems(result)

    def test_on_instrument_may_not_be_empty(self):
        text = ("TestType: WGS\nTestName: W\nDescription: D\nVersion: \"1.0.0\"\n"
                "TestApplicationProfiles:\n  OnInstrument: []\n")
        result = check_test_profile_file(text, "Wgs.yaml")
        assert not result.ok
        assert [place for place, _ in _problems(result)] == ["TestApplicationProfiles > OnInstrument"]

    def test_another_key_under_test_application_profiles_is_refused(self):
        text = TEST_YAML.replace("  DownstreamAnalysis:", "  Downstream:")
        result = check_test_profile_file(text, "Wgs.yaml")
        assert ("TestApplicationProfiles > Downstream",
                "is not a key this file can have (check the spelling)") in _problems(result)

    def test_an_on_instrument_version_must_be_text(self):
        text = TEST_YAML.replace('ApplicationProfileVersion: "~=1.0"\n    - ApplicationProfileName: Dragen',
                                 'ApplicationProfileVersion: 1\n    - ApplicationProfileName: Dragen')
        result = check_test_profile_file(text, "Wgs.yaml")
        assert not result.ok
        assert [place for place, _ in _problems(result)] == [
            "TestApplicationProfiles > OnInstrument > item 1 > ApplicationProfileVersion"]

    def test_an_on_instrument_entry_takes_no_depends_on(self):
        text = TEST_YAML.replace('ApplicationProfileVersion: "~=1.0"\n    - ApplicationProfileName: Dragen',
                                 'ApplicationProfileVersion: "~=1.0"\n      DependsOn: X\n'
                                 '    - ApplicationProfileName: Dragen')
        result = check_test_profile_file(text, "Wgs.yaml")
        assert ("TestApplicationProfiles > OnInstrument > item 1 > DependsOn",
                "is not a key this file can have (check the spelling)") in _problems(result)


class TestTheOldLayout:
    """A file with the old flat list is refused, saying where the list goes."""

    OLD = ("TestType: WGS\nTestName: WGS\nDescription: Whole genome\nVersion: \"1.0.0\"\n"
           "ApplicationProfiles:\n"
           "  - ApplicationProfileName: BCLConvertNextera\n"
           "    ApplicationProfileVersion: \"~=1.0.0\"\n")

    def test_the_file_is_refused_saying_where_the_list_goes(self):
        result = check_test_profile_file(self.OLD, "Wgs.yaml")
        assert not result.ok
        assert ("ApplicationProfiles",
                "is no longer read: list these profiles under TestApplicationProfiles > "
                "OnInstrument") in _problems(result)
        assert ("TestApplicationProfiles", "is required") in _problems(result)

    def test_the_line_is_the_old_keys(self):
        result = check_test_profile_file(self.OLD, "Wgs.yaml")
        (old,) = [p for p in result.problems if p.path == ("ApplicationProfiles",)]
        assert (old.line, old.column) == (5, 1)

    def test_from_yaml_refuses_it_too(self):
        with pytest.raises(ProfileValidationError, match="is no longer read"):
            _TestProfile.from_yaml({
                "TestType": "WGS", "TestName": "WGS", "Description": "D", "Version": "1.0.0",
                "ApplicationProfiles": [{"ApplicationProfileName": "X",
                                         "ApplicationProfileVersion": "1.0.0"}],
            })


class TestProfilesForOtherTools:
    """A profile whose type is not Dragen is skipped: not built, nothing else
    in it checked."""

    @pytest.mark.parametrize("kind", ["nextflow", "snakemake", "External", "Cloud"])
    def test_it_is_skipped(self, kind):
        result = check_application_profile_file(
            PIPELINE_YAML.replace("nextflow", kind), "pipelines/NfCore.yaml")
        assert result.skipped == kind
        assert result.problems == []
        assert result.value is None
        assert not result.ok

    def test_nothing_else_in_it_is_checked(self):
        # A '/' in ApplicationName, no DataFields, keys SeqSetup does not know.
        result = check_application_profile_file(
            PIPELINE_YAML + "Unknown:\n  - anything\n", "NfCore.yaml")
        assert result.skipped == "nextflow"
        assert result.problems == []

    def test_its_text_is_still_read_by_the_rules(self):
        # An unquoted decimal: the reader refuses it in any file it reads.
        result = check_application_profile_file(
            PIPELINE_YAML.replace('"1.1"', "1.1"), "NfCore.yaml")
        assert not result.skipped
        assert not result.ok
        assert [place for place, _ in _problems(result)] == ["ApplicationProfileVersion"]

    def test_a_key_given_twice_is_refused(self):
        result = check_application_profile_file(
            PIPELINE_YAML + "ApplicationType: nextflow\n", "NfCore.yaml")
        assert not result.skipped
        assert not result.ok

    @pytest.mark.parametrize("kind", ["Dragen", "dragen", " DRAGEN "])
    def test_a_dragen_profile_is_checked_and_built(self, kind):
        result = check_application_profile_file(
            DRAGEN_YAML.replace("ApplicationType: Dragen", f'ApplicationType: "{kind}"'), "B.yaml")
        assert result.ok, result.problems
        assert not result.skipped
        assert result.value.ApplicationName == "BCLConvert"

    @pytest.mark.parametrize("name", ["BCLConvert", "bclconvert", "DragenGermline"])
    def test_an_illumina_application_of_another_type_is_refused(self, name):
        text = (DRAGEN_YAML.replace("ApplicationType: Dragen", "ApplicationType: BclConvert")
                .replace("ApplicationName: BCLConvert", f"ApplicationName: {name}"))
        result = check_application_profile_file(text, "B.yaml")
        assert not result.skipped
        assert not result.ok
        assert ("ApplicationType",
                f"must be Dragen: {name} is one of Illumina's applications, which SeqSetup "
                "writes into the Sample Sheet") in _problems(result)

    @pytest.mark.parametrize("line", ["", "ApplicationType: 7\n", "ApplicationType: ''\n"],
                             ids=["missing", "number", "empty"])
    def test_a_profile_with_no_type_is_refused_not_skipped(self, line):
        text = PIPELINE_YAML.replace("ApplicationType: nextflow\n", line)
        result = check_application_profile_file(text, "NfCore.yaml")
        assert not result.skipped
        assert not result.ok

    def test_a_file_that_is_not_a_map_is_refused(self):
        result = check_application_profile_file("- a\n- b\n", "NfCore.yaml")
        assert not result.skipped
        assert not result.ok

    def test_from_yaml_never_skips(self):
        # Only the sync and the settings command skip a file; a profile built
        # from data is checked in full.
        with pytest.raises(ProfileValidationError):
            ApplicationProfile.from_yaml({
                "ApplicationProfileName": "NfCore", "ApplicationProfileVersion": "1.1",
                "ApplicationType": "nextflow", "ApplicationName": "nf-core/raredisease"})


def _run(description="Whole genome run") -> SequencingRun:
    sample = Sample(sample_id="S1", test_id="WGS", test_version="1.0.0", lanes=[1])
    sample.index_pair = IndexPair(
        id="p1", name="p1",
        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
    )
    return SequencingRun(
        run_name="Run1", run_description=description,
        instrument_platform=InstrumentPlatform.MISEQ, run_cycles=RunCycles(151, 151, 8, 8),
        created_by="tester", samples=[sample],
    )


def _header(sheet: str) -> list[str]:
    lines = sheet.splitlines()
    return lines[lines.index("[Header]") + 1:lines.index("")]


def _v2(run) -> str:
    test_repo, app_repo = _repos([_app("BCLConvertNextera")], [_test("WGS", ("BCLConvertNextera", "1.0.0"))])
    return SampleSheetV2Exporter.export(run, test_repo, app_repo)


class TestTheRunsUuidInTheSheet:
    """RunDescription carries the run's id, which the NovaSeq X keeps (it
    leaves out custom keys such as Custom_UUID)."""

    def test_run_description_is_the_runs_id_after_run_name(self):
        run = _run()
        header = _header(_v2(run))
        assert header[1:3] == ["RunName,Run1", f"RunDescription,{run.id}"]

    def test_custom_uuid_stays(self):
        run = _run()
        assert f"Custom_UUID,{run.id}" in _header(_v2(run))

    def test_the_typed_description_is_not_in_the_v2_sheet(self):
        assert "Whole genome run" not in _v2(_run())

    def test_a_run_with_no_description_still_has_its_id(self):
        run = _run(description="")
        assert f"RunDescription,{run.id}" in _header(_v2(run))

    def test_the_v1_sheet_keeps_the_typed_description(self):
        run = _run()
        header = _header(SampleSheetV1Exporter.export(run))
        assert "Description,Whole genome run" in header
        assert not any(line.startswith("RunDescription,") for line in header)
        assert f"Custom_UUID,{run.id}" in header
