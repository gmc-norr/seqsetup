"""Tests for tools/check_broken_samplesheets.py (read-only server check)."""

import mongomock

from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter
from tools.check_broken_samplesheets import (
    check_runs,
    find_problems,
    untranslated_names,
)

DEFAULT_UNTRANSLATED = {"IndexI7", "IndexI5"}

# What the pre-fix exporter wrote for sample S1 on lanes [1, 2] with the
# shipped BCLConvertNextera profile: untranslated header, lane 2 row missing.
OLD_SHEET = """[Header]
FileFormatVersion,2
RunName,r

[Reads]
Read1Cycles,151

[BCLConvert_Settings]
SoftwareVersion,4.1.23

[BCLConvert_Data]
Sample_ID,Lane,IndexI7,IndexI5,OverrideCycles
S1,1,ACGTACGTAC,TTGGCCAATT,Y151;I10;I10;Y151

[Cloud_Settings]
GeneratedVersion,2.7.0

[Cloud_Data]
Sample_ID,ProjectName,LibraryName
S1,r,S1_ACGTACGTAC_TTGGCCAATT
"""


def _sheet(data_section: str) -> str:
    return (
        "[Header]\nFileFormatVersion,2\n\n"
        f"[BCLConvert_Data]\n{data_section}\n"
        "[Cloud_Data]\nSample_ID,ProjectName,LibraryName\n"
    )


def _FakeDb(runs, app_profiles=()):
    """mongomock database, so check_runs' real query and projection apply."""
    db = mongomock.MongoClient()["seqsetup"]
    if runs:
        db["runs"].insert_many([dict(r) for r in runs])
    if app_profiles:
        db["application_profiles"].insert_many([dict(p) for p in app_profiles])
    return db


def _run_doc(name, status, sheet, samples):
    return {
        "_id": f"id-{name}",
        "run_name": name,
        "status": status,
        "generated_samplesheet_v2": sheet,
        "samples": samples,
    }


class TestFindProblems:
    """find_problems flags the two profile-export bugs in a saved v2 sheet."""

    def test_sheet_from_fixed_exporter_has_no_problems(self):
        profile = ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="Dragen",
            application_name="BCLConvert",
            data_fields=["Sample_ID", "Lane", "IndexI7", "IndexI5"],
            translate={"IndexI7": "Index", "IndexI5": "Index2"},
        )
        sample = Sample(
            sample_id="S1",
            test_id="WGS", test_version="1",
            lanes=[1, 2],
            index_pair=IndexPair(
                id="p1",
                name="p1",
                index1=Index(name="i7", sequence="ACGTACGTAC", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="TTGGCCAATT", index_type=IndexType.I5),
            ),
        )
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[sample],
        )

        class _TestRepo:
            def list_by_test_type(self, test_type):
                return [TestProfile(
                    test_type="WGS", test_name="WGS", version="1.0.0",
                    application_profiles=[ApplicationProfileReference(
                        profile_name="BCLConvertNextera", profile_version="1.0.0")],
                )]

        class _AppRepo:
            def get_by_name_version(self, name, version):
                return profile

        sheet = SampleSheetV2Exporter.export(run, _TestRepo(), _AppRepo())
        assert find_problems(sheet, [sample.to_dict()], DEFAULT_UNTRANSLATED) == []

    def test_old_sheet_is_flagged_for_both_bugs(self):
        problems = find_problems(
            OLD_SHEET, [{"sample_id": "S1", "lanes": [1, 2]}], DEFAULT_UNTRANSLATED
        )
        assert problems == [
            "[BCLConvert_Data] header has untranslated column(s): IndexI7, IndexI5",
            "[BCLConvert_Data] sample S1: no row for lane(s) 2",
        ]

    def test_all_lane_rows_present_is_not_flagged(self):
        sheet = _sheet("Sample_ID,Lane,Index,Index2\nS1,1,ACGT,TTGG\nS1,2,ACGT,TTGG\n")
        assert find_problems(
            sheet, [{"sample_id": "S1", "lanes": [1, 2]}], DEFAULT_UNTRANSLATED
        ) == []

    def test_no_lane_column_is_not_flagged_for_lanes(self):
        sheet = _sheet("Sample_ID,Index,Index2\nS1,ACGT,TTGG\n")
        assert find_problems(
            sheet, [{"sample_id": "S1", "lanes": [1, 2]}], DEFAULT_UNTRANSLATED
        ) == []

    def test_sample_without_lanes_is_not_flagged(self):
        sheet = _sheet("Sample_ID,Lane,Index,Index2\nS1,,ACGT,TTGG\n")
        assert find_problems(
            sheet, [{"sample_id": "S1", "lanes": []}], DEFAULT_UNTRANSLATED
        ) == []

    def test_apostrophe_escaped_sample_id_counts_as_present(self):
        sheet = _sheet("Sample_ID,Lane,Index,Index2\n'-S1,1,ACGT,TTGG\n'-S1,2,ACGT,TTGG\n")
        assert find_problems(
            sheet, [{"sample_id": "-S1", "lanes": [1, 2]}], DEFAULT_UNTRANSLATED
        ) == []

    def test_quoted_sample_id_counts_as_present(self):
        sheet = _sheet('Sample_ID,Lane,Index,Index2\n"S,1",1,ACGT,TTGG\n')
        assert find_problems(
            sheet, [{"sample_id": "S,1", "lanes": [1]}], DEFAULT_UNTRANSLATED
        ) == []

    def test_other_data_sections_are_checked_for_untranslated_header(self):
        sheet = (
            "[BCLConvert_Data]\nSample_ID,Index,Index2\nS1,ACGT,TTGG\n\n"
            "[DragenGermline_Data]\nSample_ID,RefGenome\nS1,hg38\n"
        )
        assert find_problems(
            sheet, [{"sample_id": "S1", "lanes": []}], {"RefGenome"}
        ) == ["[DragenGermline_Data] header has untranslated column(s): RefGenome"]

    def test_repeated_section_names_are_all_checked(self):
        # Two BCLConvert profiles in one run produce two [BCLConvert_Data]
        # sections; a clean second one must not hide a broken first one.
        sheet = (
            "[BCLConvert_Data]\nSample_ID,Lane,IndexI7\nS1,1,ACGT\n\n"
            "[BCLConvert_Data]\nSample_ID,Lane,Index\nS2,1,TTGG\nS2,2,TTGG\n"
        )
        problems = find_problems(
            sheet,
            [{"sample_id": "S1", "lanes": [1, 2]}, {"sample_id": "S2", "lanes": [1, 2]}],
            DEFAULT_UNTRANSLATED,
        )
        assert problems == [
            "[BCLConvert_Data] header has untranslated column(s): IndexI7",
            "[BCLConvert_Data] sample S1: no row for lane(s) 2",
        ]

    def test_lanes_checked_only_in_bclconvert_data(self):
        # Only BCLConvert rows are per lane; other sections keep one row.
        sheet = (
            "[BCLConvert_Data]\nSample_ID,Lane,Index\nS1,1,ACGT\nS1,2,ACGT\n\n"
            "[DragenGermline_Data]\nSample_ID,Lane\nS1,1\n"
        )
        assert find_problems(
            sheet, [{"sample_id": "S1", "lanes": [1, 2]}], DEFAULT_UNTRANSLATED
        ) == []

    def test_invalid_stored_lanes_are_ignored_like_the_model(self):
        # Sample.__setattr__ keeps only positive ints, so the exporter never
        # saw '1', True or 0 — expecting rows for them would be a false alarm.
        sheet = _sheet("Sample_ID,Lane,Index\nS1,2,ACGT\n")
        assert find_problems(
            sheet, [{"sample_id": "S1", "lanes": ["1", True, 0, 2]}], DEFAULT_UNTRANSLATED
        ) == []


class TestUntranslatedNames:
    """untranslated_names collects Translate source names from all profiles."""

    def test_includes_profile_translate_keys_and_defaults(self):
        names = untranslated_names([{"translate": {"RefGenomeDir": "ReferenceDir"}}])
        assert names == {"IndexI7", "IndexI5", "RefGenomeDir"}

    def test_ignores_identity_mappings_and_missing_translate(self):
        names = untranslated_names([{"translate": {"Index": "Index"}}, {}])
        assert names == {"IndexI7", "IndexI5"}

    def test_ignores_non_dict_translate(self):
        names = untranslated_names([{"translate": ["IndexI7"]}, {"translate": None}])
        assert names == {"IndexI7", "IndexI5"}


class TestCheckRuns:
    """check_runs reads Ready/Archived runs only and reports them by status."""

    def test_reports_broken_ready_and_archived_runs_separately(self):
        db = _FakeDb([
            _run_doc("R1", "ready", OLD_SHEET, [{"sample_id": "S1", "lanes": [1, 2]}]),
            _run_doc("A1", "archived", OLD_SHEET, [{"sample_id": "S1", "lanes": [1]}]),
        ])
        report, broken = check_runs(db)
        assert broken == 2
        ready_part, archived_part = report.split("ARCHIVED")
        assert "R1" in ready_part and "A1" not in ready_part
        assert "A1" in archived_part
        assert "no row for lane(s) 2" in ready_part

    def test_legacy_complete_status_is_reported_as_archived(self):
        # SequencingRun.from_dict loads the pre-rename status "complete" as
        # ARCHIVED, and the API serves its saved sheet.
        db = _FakeDb([
            _run_doc("C1", "complete", OLD_SHEET, [{"sample_id": "S1", "lanes": [1]}]),
        ])
        report, broken = check_runs(db)
        assert broken == 1
        assert "C1" in report.split("ARCHIVED")[1]

    def test_ready_advice_warns_sheet_may_already_have_been_used(self):
        db = _FakeDb([
            _run_doc("R1", "ready", OLD_SHEET, [{"sample_id": "S1", "lanes": [1]}]),
        ])
        report, _ = check_runs(db)
        ready_part = report.split("ARCHIVED")[0]
        assert "may already have been downloaded" in ready_part

    def test_draft_runs_are_not_checked(self):
        db = _FakeDb([
            _run_doc("D1", "draft", OLD_SHEET, [{"sample_id": "S1", "lanes": [1, 2]}]),
        ])
        report, broken = check_runs(db)
        assert broken == 0
        assert "D1" not in report

    def test_runs_without_saved_sheet_are_counted_not_flagged(self):
        db = _FakeDb([_run_doc("R1", "ready", None, [])])
        report, broken = check_runs(db)
        assert broken == 0
        assert "1 run(s) have no saved v2 sheet" in report

    def test_clean_runs_report_zero(self):
        clean = _sheet("Sample_ID,Lane,Index,Index2\nS1,1,ACGT,TTGG\n")
        db = _FakeDb([_run_doc("R1", "ready", clean, [{"sample_id": "S1", "lanes": [1]}])])
        report, broken = check_runs(db)
        assert broken == 0
        assert "No broken Sample Sheets found." in report

    def test_profile_translate_keys_from_db_are_used(self):
        sheet = _sheet("Sample_ID,MyI7\nS1,ACGT\n")
        db = _FakeDb(
            [_run_doc("R1", "ready", sheet, [{"sample_id": "S1", "lanes": []}])],
            app_profiles=[{"translate": {"MyI7": "Index"}}],
        )
        report, broken = check_runs(db)
        assert broken == 1
        assert "untranslated column(s): MyI7" in report
