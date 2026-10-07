"""The sheet plan: which samples go in which application section, from which
profile, the mismatch numbers the sheet gives BCL Convert, and every reason
the sheet cannot be written (spec 2026-10-05 group A3, §1, §2)."""

from pathlib import Path

import mongomock
import pytest
import yaml

from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.models.test_profile import TestProfile as _TestProfile
from seqsetup.repositories.application_profile_repo import ApplicationProfileRepository
from seqsetup.repositories.test_profile_repo import TestProfileRepository as _TestRepo
from seqsetup.services.sheet_plan import data_columns, full_reads, plan_sheet

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "profiles"
BCL_FIELDS = ["Sample_ID", "Lane", "Index", "Index2", "OverrideCycles",
              "BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"]
BCL_DATA = {"BarcodeMismatchesIndex1": 1, "BarcodeMismatchesIndex2": 1}


def _app(name, application="BCLConvert", version="1.0.0", settings=None, data=None,
         fields=None, translate=None) -> ApplicationProfile:
    """A profile as the database stores it: built directly, past the sync's
    check, which refuses several of these shapes."""
    return ApplicationProfile(
        name=name, version=version, application_name=application, application_type="Dragen",
        settings={"SoftwareVersion": "4.3.6"} if settings is None else settings,
        data=dict(BCL_DATA) if data is None else data,
        data_fields=list(BCL_FIELDS) if fields is None else fields,
        translate=translate or {}, source_file=f"{name}.yaml",
    )


def _dragen(name, application="DragenGermline", **kw) -> ApplicationProfile:
    kw.setdefault("data", {"ReferenceGenomeDir": "hg38"})
    kw.setdefault("fields", ["Sample_ID", "ReferenceGenomeDir"])
    return _app(name, application, **kw)


def _test(test_type, *refs) -> _TestProfile:
    return _TestProfile.from_yaml({
        "TestType": test_type, "TestName": test_type, "Description": test_type,
        "Version": "1.0.0",
        "ApplicationProfiles": [{"ApplicationProfileName": n, "ApplicationProfileVersion": v}
                                for n, v in refs],
    }, f"{test_type}.yaml")


def _repos(apps=(), tests=()):
    db = mongomock.MongoClient()["plan"]
    test_repo, app_repo = _TestRepo(db), ApplicationProfileRepository(db)
    for profile in apps:
        app_repo.save(profile)
    for profile in tests:
        test_repo.save(profile)
    return test_repo, app_repo


def _sample(sample_id, test="WGS", i7="ACGTACGTAC", i5="TTGGCCAATT", lanes=(1,)) -> Sample:
    sample = Sample(sample_id=sample_id, test_id=test, lanes=list(lanes))
    if i5 is None:
        sample.assign_index1(Index(name=f"{sample_id}7", sequence=i7, index_type=IndexType.I7))
    else:
        sample.index_pair = IndexPair(
            id=f"p{sample_id}", name=f"p{sample_id}",
            index1=Index(name=f"{sample_id}7", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"{sample_id}5", sequence=i5, index_type=IndexType.I5),
        )
    return sample


def _run(*samples, cycles=RunCycles(151, 151, 10, 10), **fields) -> SequencingRun:
    return SequencingRun(run_name="Plan", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                         flowcell_type="10B", run_cycles=cycles, samples=list(samples), **fields)


def _plan(run, apps, tests, lanes=8):
    test_repo, app_repo = _repos(apps, tests)
    return plan_sheet(run, test_repo, app_repo, lanes)


def _problems(plan, category):
    return [p for p in plan.problems if p.category == category]


def _wgs():
    return [_app("BCLX"), _dragen("GermX")], [_test("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0"))]


class TestTheHelpers:
    def test_data_columns_follow_the_writer(self):
        profile = _app("T", fields=["Sample_ID", "IndexI7"], translate={"IndexI7": "Index"})
        assert data_columns(profile) == [("Sample_ID", "Sample_ID"), ("IndexI7", "Index")]
        no_fields = _app("U", fields=[], data={"Sample_ID": "", "Lane": ""})
        assert data_columns(no_fields) == [("Sample_ID", "Sample_ID"), ("Lane", "Lane")]

    def test_full_reads(self):
        assert full_reads(_run()) == "Y151;I10;I10;Y151"
        assert full_reads(_run(cycles=RunCycles(151, 0, 8, 0))) == "Y151;I8"


class TestARunWithoutProblems:
    """Today's sections: one per profile, samples by test, then run order."""

    def test_two_sections_in_order(self):
        apps, tests = _wgs()
        s1, s2 = _sample("S1"), _sample("S2", i7="TGCATGCAAC", i5="CCAATTGGTT")
        plan = _plan(_run(s1, s2), apps, tests)
        assert plan.problems == [] and plan.warnings == []
        assert [s.application for s in plan.sections] == ["BCLConvert", "DragenGermline"]
        assert [(sample.sample_id, p.name) for sample, p in plan.sections[0].rows] == [
            ("S1", "BCLX"), ("S2", "BCLX")]
        assert plan.mismatches == {(s1.id, 1): 1, (s1.id, 2): 1, (s2.id, 1): 1, (s2.id, 2): 1}

    def test_samples_are_grouped_by_test_in_order_of_first_sample(self):
        apps = [_app("BCLX"), _dragen("GermX"), _dragen("RnaX", "DragenRna")]
        tests = [_test("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0")),
                 _test("RNA", ("BCLX", "1.0.0"), ("RnaX", "1.0.0"))]
        samples = [_sample("R1", "RNA"), _sample("W1", "WGS", i7="TGCATGCAAC"),
                   _sample("R2", "RNA", i7="GGGGCCCCAA")]
        plan = _plan(_run(*samples), apps, tests)
        assert [s.application for s in plan.sections] == ["BCLConvert", "DragenRna", "DragenGermline"]
        assert [sample.sample_id for sample, _ in plan.sections[0].rows] == ["R1", "R2", "W1"]


class TestOneSectionPerApplication:
    """Profiles for one application share its section (spec §1)."""

    def test_one_profile_by_two_constraints_is_one_section(self):
        apps = [_app("BCLX", version="1.0")]
        tests = [_test("WGS", ("BCLX", "1.0")), _test("EXOME", ("BCLX", "~=1.0"))]
        plan = _plan(_run(_sample("S1"), _sample("S2", "EXOME", i7="TGCATGCAAC")), apps, tests)
        assert plan.problems == []
        (section,) = plan.sections
        assert [p.name for p in section.profiles] == ["BCLX"]
        assert [sample.sample_id for sample, _ in section.rows] == ["S1", "S2"]

    def test_the_shipped_germline_and_somatic_profiles_share_one_section(self):
        def shipped(name):
            path = SHIPPED / "application_profiles" / "dragen" / name
            return ApplicationProfile.from_yaml(yaml.safe_load(path.read_text()), name)
        apps = [_app("BCLX"), shipped("DragenEnrichmentIdtGermline.yaml"),
                shipped("DragenEnrichmentIdtSomatic.yaml")]
        tests = [_test("GERM", ("BCLX", "1.0.0"), ("DragenEnrichmentGermline", "1.0.0")),
                 _test("SOM", ("BCLX", "1.0.0"), ("DragenEnrichmentSomatic", "1.0.0"))]
        plan = _plan(_run(_sample("G1", "GERM"), _sample("T1", "SOM", i7="TGCATGCAAC")),
                     apps, tests)
        assert plan.problems == []
        enrichment = plan.sections[1]
        assert enrichment.application == "DragenEnrichment"
        assert [(s.sample_id, p.name) for s, p in enrichment.rows] == [
            ("G1", "DragenEnrichmentGermline"), ("T1", "DragenEnrichmentSomatic")]


class TestTheWritersOwnProblems:
    """Problem 1: reported by the checks already, so no category; the writer
    stops on them."""

    def test_a_sample_without_a_test(self):
        apps, tests = _wgs()
        plan = _plan(_run(_sample("S1", test="")), apps, tests)
        assert [(p.category, p.message) for p in plan.problems] == [
            ("", "Sample S1 has no test, so it would not be on the Sample Sheet.")]
        assert plan.check_errors == []

    def test_a_test_without_a_test_profile(self):
        apps, _tests = _wgs()
        plan = _plan(_run(_sample("S1")), apps, [])
        assert [p.message for p in plan.problems] == ["Test 'WGS' has no test profile."]

    def test_a_profile_that_is_not_stored(self):
        apps, tests = _wgs()
        plan = _plan(_run(_sample("S1")), apps[1:], tests)
        assert [p.message for p in plan.problems] == [
            "Test 'WGS' lists BCLX 1.0.0, which is not stored."]
        assert plan.check_errors == []


class TestATestWithoutABCLConvertProfile:
    def test_the_message(self):
        apps = [_dragen("GermX")]
        tests = [_test("DRAGEN_ONLY", ("GermX", "1.0.0"))]
        plan = _plan(_run(_sample("S1", "DRAGEN_ONLY")), apps, tests)
        (problem,) = _problems(plan, "test_without_bclconvert_profile")
        assert problem.message == (
            "Test 'DRAGEN_ONLY' has no BCLConvert profile, so its 1 sample(s) would not be "
            "demultiplexed: S1. Add one BCLConvert profile to the test profile.")
        assert problem.sample_names == ("S1",)

    def test_not_beside_a_profile_that_is_not_stored(self):
        plan = _plan(_run(_sample("S1")), [_dragen("GermX")], _wgs()[1])
        assert _problems(plan, "test_without_bclconvert_profile") == []


class TestATestWithTwoProfilesForOneApplication:
    def test_two_bclconvert_profiles(self):
        apps = [_app("BCLX"), _app("BCLY")]
        tests = [_test("WGS", ("BCLX", "1.0.0"), ("BCLY", "1.0.0"))]
        (problem,) = _problems(_plan(_run(_sample("S1")), apps, tests),
                               "test_with_two_profiles_for_one_application")
        assert problem.message == (
            "Test 'WGS' lists 2 profiles for BCLConvert: BCLX 1.0.0, BCLY 1.0.0. A test may "
            "list one profile per application, once.")

    def test_one_profile_listed_twice(self):
        apps = [_app("BCLX")]
        tests = [_test("WGS", ("BCLX", "1.0.0"), ("BCLX", "~=1.0.0"))]
        plan = _plan(_run(_sample("S1")), apps, tests)
        assert len(_problems(plan, "test_with_two_profiles_for_one_application")) == 1
        assert [sample.sample_id for sample, _ in plan.sections[0].rows] == ["S1"]


class TestProfilesThatDifferInOneSection:
    @pytest.mark.parametrize("second,what", [
        (dict(settings={"SoftwareVersion": "4.3.6", "FastqCompressionFormat": "gzip"}), "Settings"),
        (dict(fields=BCL_FIELDS[:-1]), "columns"),
        (dict(settings={}, fields=BCL_FIELDS[:-1]), "Settings and columns"),
    ])
    def test_the_message(self, second, what):
        apps = [_app("BCLX"), _app("BCLY", **second)]
        tests = [_test("WGS", ("BCLX", "1.0.0")), _test("PANEL", ("BCLY", "1.0.0"))]
        plan = _plan(_run(_sample("S1"), _sample("S2", "PANEL", i7="TGCATGCAAC")), apps, tests)
        (problem,) = _problems(plan, "profiles_differ_in_one_section")
        assert problem.message == (
            f"BCLConvert: profiles BCLX 1.0.0 (test WGS) and BCLY 1.0.0 (test PANEL) have "
            f"different {what}, and a Sample Sheet has one [BCLConvert_Settings] and one "
            f"[BCLConvert_Data] section. Put these tests in separate runs, or give the "
            f"profiles the same Settings and columns.")

    def test_profiles_that_match_share_it(self):
        apps = [_app("BCLX"), _app("BCLY", data={"BarcodeMismatchesIndex1": 0,
                                                 "BarcodeMismatchesIndex2": 0})]
        tests = [_test("WGS", ("BCLX", "1.0.0")), _test("PANEL", ("BCLY", "1.0.0"))]
        plan = _plan(_run(_sample("S1"), _sample("S2", "PANEL", i7="TGCATGCAAC")), apps, tests)
        assert plan.problems == []
        assert [p.name for p in plan.sections[0].profiles] == ["BCLX", "BCLY"]


class TestColumnsAndNames:
    def test_a_repeated_column(self):
        apps = [_app("BCLX", fields=["Sample_ID", "Lane", "IndexI7", "IndexI5"],
                     translate={"IndexI7": "Index", "IndexI5": "Index"}), _dragen("GermX")]
        (problem,) = _problems(_plan(_run(_sample("S1")), apps, _wgs()[1]), "repeated_column")
        assert problem.message == (
            "Profile BCLX 1.0.0 writes the column Index more than once (from IndexI7, IndexI5). "
            "Each column may appear once, whatever its case; check its DataFields and Translate.")

    def test_a_column_repeated_in_another_case(self):
        apps = [_app("BCLX"), _dragen("GermX", fields=["Sample_ID", "sample_id"])]
        assert len(_problems(_plan(_run(_sample("S1")), apps, _wgs()[1]), "repeated_column")) == 1

    @pytest.mark.parametrize("profile,where,canonical,written", [
        (dict(fields=["Sample_ID", "Lane", "index", "Index2", "OverrideCycles"], data={}),
         "its columns", "Index", "index"),
        (dict(fields=BCL_FIELDS[:-1] + ["barcodemismatchesindex2"],
              data={"BarcodeMismatchesIndex1": 1, "barcodemismatchesindex2": 2}),
         "its columns", "BarcodeMismatchesIndex2", "barcodemismatchesindex2"),
        (dict(settings={"SoftwareVersion": "4.3.6", "barcodeMismatchesIndex1": 2},
              fields=BCL_FIELDS[:5] + ["BarcodeMismatchesIndex2"]),
         "Settings", "BarcodeMismatchesIndex1", "barcodeMismatchesIndex1"),
        (dict(settings={"softwareversion": "999.0"}), "Settings", "SoftwareVersion",
         "softwareversion"),
    ])
    def test_another_spelling_is_refused(self, profile, where, canonical, written):
        apps = [_app("BCLX", **profile), _dragen("GermX")]
        (problem,) = _problems(_plan(_run(_sample("S1")), apps, _wgs()[1]),
                               "name_spelled_otherwise")
        assert problem.message == (
            f"Profile BCLX 1.0.0 spells {canonical} as '{written}' (in {where}). SeqSetup "
            f"fills and reads only the spelling {canonical}, so the Sample Sheet would not "
            f"carry what was checked.")

    def test_softwareversion_is_spelled_exactly_in_a_dragen_profile_too(self):
        apps = [_app("BCLX"), _dragen("GermX", settings={"softwareversion": "999.0"})]
        (problem,) = _problems(_plan(_run(_sample("S1")), apps, _wgs()[1]),
                               "name_spelled_otherwise")
        assert problem.message.startswith("Profile GermX 1.0.0 spells SoftwareVersion as ")

    def test_a_setting_in_two_places(self):
        apps = [_app("BCLX", settings={"SoftwareVersion": "4.3.6", "barcodemismatchesindex1": 1},
                     fields=BCL_FIELDS), _dragen("GermX")]
        plan = _plan(_run(_sample("S1")), apps, _wgs()[1])
        (problem,) = _problems(plan, "setting_in_two_places")
        assert problem.message == (
            "barcodemismatchesindex1 would be set both in [BCLConvert_Settings] (profile BCLX "
            "1.0.0) and as a column in [BCLConvert_Data] (profile BCLX 1.0.0). BCL Convert "
            "allows a setting in one place only.")

    def test_a_run_setting_in_two_places(self):
        apps = [_app("BCLX", fields=BCL_FIELDS + ["AdapterBehavior"],
                     data=dict(BCL_DATA, AdapterBehavior="trim")), _dragen("GermX")]
        plan = _plan(_run(_sample("S1"), adapter_behavior="mask"), apps, _wgs()[1])
        (problem,) = _problems(plan, "setting_in_two_places")
        assert problem.message.startswith(
            "AdapterBehavior would be set both in [BCLConvert_Settings] (the run's setting)")


class TestTheColumnsASampleNeeds:
    """Problem 8: the BCLConvert profile has a column for every value a
    sample needs, and no cell it needs is empty."""

    def _one(self, profile, *samples, **run_fields):
        plan = _plan(_run(*samples, **run_fields), [profile, _dragen("GermX")], _wgs()[1])
        return plan

    @pytest.mark.parametrize("dropped,column,reason", [
        ("Index", "Index", "they have an i7"),
        ("Index2", "Index2", "they have an i5"),
        ("OverrideCycles", "OverrideCycles",
         "their OverrideCycles is not the run's full reads (Y151;I10;I10;Y151)"),
    ])
    def test_a_missing_column(self, dropped, column, reason):
        profile = _app("BCLX", fields=[f for f in BCL_FIELDS if f != dropped])
        sample = _sample("S1", i7="ACGTACGT", i5="TTGGCCAA")
        (problem,) = _problems(self._one(profile, sample), "bclconvert_column_missing")
        assert problem.message == (
            f"1 sample(s) need a {column} column that BCLConvert profile BCLX 1.0.0 does not "
            f"have, because {reason}: S1. Add {column} to the profile's DataFields.")

    def test_a_missing_lane_column(self):
        profile = _app("BCLX", fields=[f for f in BCL_FIELDS if f != "Lane"])
        plan = self._one(profile, _sample("S1", lanes=[1, 2]),
                         _sample("S2", i7="TGCATGCAAC", lanes=list(range(1, 9))))
        (problem,) = _problems(plan, "bclconvert_column_missing")
        assert problem.sample_names == ("S1",)
        assert "because they are on some lanes only: S1." in problem.message

    def test_full_reads_need_no_overridecycles_column(self):
        profile = _app("BCLX", fields=[f for f in BCL_FIELDS if f != "OverrideCycles"])
        assert _problems(self._one(profile, _sample("S1")), "bclconvert_column_missing") == []

    def test_lanes_not_picked(self):
        (problem,) = _problems(self._one(_app("BCLX"), _sample("S1", lanes=())), "lanes_not_picked")
        assert problem.message == (
            "1 sample(s) have no lanes picked, but BCLConvert profile BCLX 1.0.0 has a Lane "
            "column, so their Lane cell would be empty: S1. Pick their lanes.")

    @pytest.mark.parametrize("default", ["", "na"])
    def test_an_empty_mismatch_cell(self, default):
        profile = _app("BCLX", data={"BarcodeMismatchesIndex1": default,
                                     "BarcodeMismatchesIndex2": 1})
        sample = _sample("S1")
        sample.barcode_mismatches_index1 = None
        (problem,) = _problems(self._one(profile, sample), "mismatch_cell_empty")
        assert problem.message == (
            "1 sample(s) would get an empty BarcodeMismatchesIndex1 cell from BCLConvert profile "
            "BCLX 1.0.0: S1. Set their mismatch number, or give the profile a Data default for "
            "BarcodeMismatchesIndex1.")

    def test_no_empty_cell_complaint_for_an_index_the_sample_lacks(self):
        profile = _app("BCLX", data={"BarcodeMismatchesIndex1": 1, "BarcodeMismatchesIndex2": ""})
        sample = _sample("S1", i5=None)
        sample.barcode_mismatches_index2 = None
        assert _problems(self._one(profile, sample), "mismatch_cell_empty") == []


class TestTheMismatchNumbers:
    """The number the sheet gives BCL Convert for each sample (spec §2)."""

    def test_the_samples_number_in_its_column(self):
        sample = _sample("S1")
        sample.barcode_mismatches_index1 = 0
        plan = _plan(_run(sample), *_wgs())
        assert plan.mismatches[(sample.id, 1)] == 0

    def test_a_cleared_sample_gets_the_data_default(self):
        profile = _app("BCLX", data={"BarcodeMismatchesIndex1": 2, "BarcodeMismatchesIndex2": 1})
        sample = _sample("S1")
        sample.barcode_mismatches_index1 = None
        plan = _plan(_run(sample), [profile, _dragen("GermX")], _wgs()[1])
        assert plan.mismatches[(sample.id, 1)] == 2

    def test_without_the_column_the_settings_number_and_a_warning(self):
        profile = _app("BCLX", settings={"SoftwareVersion": "4.3.6", "BarcodeMismatchesIndex1": 0,
                                         "BarcodeMismatchesIndex2": 0},
                       fields=BCL_FIELDS[:5], data={})
        s1, s2 = _sample("S1"), _sample("S2", i7="TGCATGCAAC", i5=None)
        plan = _plan(_run(s1, s2), [profile, _dragen("GermX")], _wgs()[1])
        assert plan.problems == []
        assert plan.mismatches[(s1.id, 1)] == 0 and plan.mismatches[(s2.id, 2)] == 0
        assert [w.message for w in plan.warnings] == [
            "2 sample(s) have a mismatch number the Sample Sheet cannot carry, because "
            "BCLConvert profile BCLX 1.0.0 has no BarcodeMismatchesIndex1 column: S1, S2 (their "
            "number 1; the sheet gives BCL Convert 0). The checks use 0. To use the samples' "
            "numbers, add BarcodeMismatchesIndex1 to the profile's DataFields.",
            "1 sample(s) have a mismatch number the Sample Sheet cannot carry, because "
            "BCLConvert profile BCLX 1.0.0 has no BarcodeMismatchesIndex2 column: S1 (their "
            "number 1; the sheet gives BCL Convert 0). The checks use 0. To use the samples' "
            "numbers, add BarcodeMismatchesIndex2 to the profile's DataFields.",
        ]

    def test_without_the_column_or_a_setting_bcl_converts_default(self):
        profile = _app("BCLX", fields=BCL_FIELDS[:5], data={})
        sample = _sample("S1")
        sample.barcode_mismatches_index1 = 2
        plan = _plan(_run(sample), [profile, _dragen("GermX")], _wgs()[1])
        assert plan.mismatches[(sample.id, 1)] == 1
        assert len(plan.warnings) == 1


class TestTheFingerprint:
    """A hash of the profiles' content and the lane count (spec §1)."""

    def test_what_every_sync_renews_is_not_a_change(self):
        run = _run(_sample("S1"))
        first = _plan(run, *_wgs()).fingerprint
        assert _plan(run, *_wgs()).fingerprint == first   # new ids and synced_at

    def test_a_data_default_change_is_a_change(self):
        run = _run(_sample("S1"))
        apps, tests = _wgs()
        changed = [_app("BCLX", data={"BarcodeMismatchesIndex1": 2,
                                      "BarcodeMismatchesIndex2": 1}), apps[1]]
        assert _plan(run, changed, tests).fingerprint != _plan(run, apps, tests).fingerprint

    def test_the_lane_count_is_part_of_it(self):
        run = _run(_sample("S1"))
        assert _plan(run, *_wgs(), lanes=2).fingerprint != _plan(run, *_wgs()).fingerprint

    @pytest.mark.parametrize("change", [
        "a Settings value", "the DataFields", "the Translate", "the test's list of profiles",
        "a newer version",
    ])
    def test_each_of_these_is_a_change(self, change):
        # Everything the sheet or the checks read is in the fingerprint (spec
        # §1, Tests): a narrower hash would let these through to the writer.
        # The Settings value is the plan review's case: without mismatch
        # columns, BarcodeMismatchesIndex1 0 -> 2 changes the collision check.
        run = _run(_sample("S1"))
        fields = ["Sample_ID", "Lane", "Index", "Index2", "OverrideCycles"]

        def bcl(number=0, columns=fields):
            return _app("BCLX", settings={"SoftwareVersion": "4.3.6",
                                          "BarcodeMismatchesIndex1": number},
                        fields=list(columns), data={})

        apps, refs = [bcl(), _dragen("GermX")], [("BCLX", "1.0.0"), ("GermX", "~=1.0")]
        after_apps, after_refs = list(apps), list(refs)
        if change == "a Settings value":
            after_apps[0] = bcl(2)
        elif change == "the DataFields":
            after_apps[0] = bcl(columns=fields[:-1])
        elif change == "the Translate":
            after_apps[1] = _dragen("GermX", translate={"ReferenceGenomeDir": "RefDir"})
        elif change == "the test's list of profiles":
            after_refs = [("BCLX", "1.0.0"), ("GermX", "1.0.0")]
        else:
            after_apps.append(_dragen("GermX", version="1.0.1"))
        before = _plan(run, apps, [_test("WGS", *refs)]).fingerprint
        assert _plan(run, after_apps, [_test("WGS", *after_refs)]).fingerprint != before
