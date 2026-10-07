"""The v2 writer writes from the sheet plan (spec 2026-10-05 group A3, §1):
one section per application, each row from its own profile; it stops on a
problem, and on a plan whose fingerprint is not the one the checks passed."""

from datetime import datetime
from pathlib import Path

import pytest
import yaml

from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.models.test_profile import TestProfile as _TestProfile
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter
from seqsetup.services.sheet_plan import (
    PROFILES_CHANGED,
    SheetPlanChanged,
    SheetPlanProblem,
    plan_sheet,
)

from .test_sheet_plan import _app, _dragen, _repos, _run, _sample, _test, _wgs

SHIPPED = Path(__file__).resolve().parents[2] / "config" / "profiles"

# The sheet main (9be63ce) writes for this run with the shipped profiles.
TODAY = """[Header]
FileFormatVersion,2
RunName,A3-today
InstrumentPlatform,NovaSeqXSeries
IndexOrientation,Forward
Custom_UUID,a3-today

[Reads]
Read1Cycles,151
Read2Cycles,151
Index1Cycles,10
Index2Cycles,10

[BCLConvert_Settings]
NoLaneSplitting,false
CreateFastqForIndexReads,0
SoftwareVersion,4.1.23
FastqCompressionFormat,gzip

[BCLConvert_Data]
Sample_ID,Lane,Index,Index2,OverrideCycles,BarcodeMismatchesIndex1,BarcodeMismatchesIndex2,AdapterRead1,AdapterRead2
S1,1,ACGTACGTAC,TTGGCCAATT,Y151;I10;I10;Y151,1,1,,
S1,2,ACGTACGTAC,TTGGCCAATT,Y151;I10;I10;Y151,1,1,,
S2,1,TGCATGCAAC,CCAATTGGTT,Y151;I10;I10;Y151,1,1,,
S2,2,TGCATGCAAC,CCAATTGGTT,Y151;I10;I10;Y151,1,1,,

[DragenGermline_Settings]
SoftwareVersion,4.1.23
AppVersion,1.2.1
MapAlignOutFormat,bam
KeepFastq,True

[DragenGermline_Data]
ReferenceGenomeDir,VariantCallingMode,QcCoverage1BedFile,QcCoverage2BedFile,QcCoverage3BedFile,QcCrossContaminationVcfFile,Sample_ID
hg38-alt_masked.cnv.graph.hla.rna-8-1667497097-2,AllVariantCallers,na,na,na,na,S1
hg38-alt_masked.cnv.graph.hla.rna-8-1667497097-2,AllVariantCallers,na,na,na,na,S2

[Cloud_Settings]
GeneratedVersion,2.7.0

[Cloud_Data]
Sample_ID,ProjectName,LibraryName
S1,A3-today,S1_ACGTACGTAC_TTGGCCAATT
S2,A3-today,S2_TGCATGCAAC_CCAATTGGTT

"""


def _shipped(name: str) -> ApplicationProfile:
    path = SHIPPED / "application_profiles" / "dragen" / name
    return ApplicationProfile.from_yaml(yaml.safe_load(path.read_text()), name)


def _today_run() -> SequencingRun:
    def sample(sid, i7, i5):
        return Sample(id=f"id-{sid}", sample_id=sid, test_id="WGS", lanes=[1, 2],
                      index_pair=IndexPair(
                          id=f"p{sid}", name=f"p{sid}",
                          index1=Index(name=f"{sid}7", sequence=i7, index_type=IndexType.I7),
                          index2=Index(name=f"{sid}5", sequence=i5, index_type=IndexType.I5)))
    return SequencingRun(
        id="a3-today", run_name="A3-today", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", created_by="tester", created_at=datetime(2026, 10, 6, 12, 0, 0),
        run_cycles=RunCycles(151, 151, 10, 10),
        samples=[sample("S1", "ACGTACGTAC", "TTGGCCAATT"), sample("S2", "TGCATGCAAC", "CCAATTGGTT")],
    )


def _export(run, apps, tests, **kw) -> str:
    test_repo, app_repo = _repos(apps, tests)
    return SampleSheetV2Exporter.export(run, test_repo, app_repo, **kw)


def _section(sheet: str, name: str) -> list[str]:
    lines = sheet.split(f"[{name}]\n", 1)[1].split("\n\n", 1)[0]
    return lines.splitlines()


class TestTodaysSheet:
    """A run whose tests share no application gets today's sheet, byte for
    byte."""

    def test_the_shipped_wgs_profiles(self):
        apps = [_shipped(f.name) for f in
                sorted((SHIPPED / "application_profiles" / "dragen").glob("*.yaml"))]
        wgs = _TestProfile.from_yaml(
            yaml.safe_load((SHIPPED / "test_profiles" / "Wgs.yaml").read_text()), "Wgs.yaml")
        assert _export(_today_run(), apps, [wgs]) == TODAY


class TestOneSectionPerApplication:
    def test_the_shipped_germline_and_somatic_profiles_share_one_section(self):
        apps = [_app("BCLX"), _shipped("DragenEnrichmentIdtGermline.yaml"),
                _shipped("DragenEnrichmentIdtSomatic.yaml")]
        tests = [_test("GERM", ("BCLX", "1.0.0"), ("DragenEnrichmentGermline", "1.0.0")),
                 _test("SOM", ("BCLX", "1.0.0"), ("DragenEnrichmentSomatic", "1.0.0"))]
        sheet = _export(_run(_sample("G1", "GERM"), _sample("T1", "SOM", i7="TGCATGCAAC")),
                        apps, tests)
        assert sheet.count("[DragenEnrichment_Settings]") == 1
        assert sheet.count("[DragenEnrichment_Data]") == 1
        assert _section(sheet, "DragenEnrichment_Data") == [
            "Sample_ID,ReferenceGenomeDir,BedFile,GermlineOrSomatic,AuxNoiseBaselineFile,"
            "AuxCnvPanelOfNormalsFile,VariantCallingMode",
            "G1,hg38-alt_masked.cnv.graph.hla.rna-8-1667497097-2,gms560_hg38.BedFile,germline,"
            "na,na,AllVariantCallers",
            "T1,hg38-alt_masked.cnv.graph.hla.rna-8-1667497097-2,gms560_hg38.BedFile,somatic,"
            "na,na,AllVariantCallers",
        ]

    def test_one_profile_by_two_constraints_is_one_section(self):
        apps = [_app("BCLX", version="1.0")]
        tests = [_test("WGS", ("BCLX", "1.0")), _test("EXOME", ("BCLX", "~=1.0"))]
        sheet = _export(_run(_sample("S1"), _sample("S2", "EXOME", i7="TGCATGCAAC")), apps, tests)
        assert sheet.count("[BCLConvert_Data]") == 1
        assert [row.split(",")[0] for row in _section(sheet, "BCLConvert_Data")[1:]] == ["S1", "S2"]

    def test_merged_rows_take_their_own_profiles_field_names(self):
        # The same columns after Translate, from different field names: each
        # row is filled through its own profile's names.
        apps = [_app("BCLX"),
                _dragen("GermA", fields=["Sample_ID", "Ref"], data={"Ref": "hg38"}),
                _dragen("GermB", fields=["Sample_ID", "RefGenome"], data={"RefGenome": "hg19"},
                        translate={"RefGenome": "Ref"})]
        tests = [_test("WGS", ("BCLX", "1.0.0"), ("GermA", "1.0.0")),
                 _test("PANEL", ("BCLX", "1.0.0"), ("GermB", "1.0.0"))]
        sheet = _export(_run(_sample("S1"), _sample("S2", "PANEL", i7="TGCATGCAAC")), apps, tests)
        assert _section(sheet, "DragenGermline_Data") == ["Sample_ID,Ref", "S1,hg38", "S2,hg19"]

    def test_merged_rows_take_their_own_profiles_data_defaults(self):
        apps = [_app("BCLX"), _app("BCLY", data={"BarcodeMismatchesIndex1": 0,
                                                 "BarcodeMismatchesIndex2": 0})]
        tests = [_test("WGS", ("BCLX", "1.0.0")), _test("PANEL", ("BCLY", "1.0.0"))]
        s1, s2 = _sample("S1"), _sample("S2", "PANEL", i7="TGCATGCAAC")
        for s in (s1, s2):
            s.barcode_mismatches_index1 = s.barcode_mismatches_index2 = None
        rows = _section(_export(_run(s1, s2), apps, tests), "BCLConvert_Data")[1:]
        assert [row.split(",")[-2:] for row in rows] == [["1", "1"], ["0", "0"]]


class TestTheWriterStops:
    """On any problem the writer raises before writing (spec §1); at Mark
    Ready that keeps the run a Draft."""

    def test_a_test_without_a_bclconvert_profile(self):
        apps, tests = [_dragen("GermX")], [_test("DRAGEN_ONLY", ("GermX", "1.0.0"))]
        with pytest.raises(SheetPlanProblem, match="Test 'DRAGEN_ONLY' has no BCLConvert profile"):
            _export(_run(_sample("S1", "DRAGEN_ONLY")), apps, tests)

    def test_a_sample_without_a_test(self):
        with pytest.raises(SheetPlanProblem,
                           match="Sample S2 has no test, so it would not be on the Sample Sheet."):
            _export(_run(_sample("S1"), _sample("S2", test="", i7="TGCATGCAAC")), *_wgs())

    def test_a_profile_that_is_not_stored(self):
        # The DI-07 timing: a sync deleted the profiles after the checks.
        with pytest.raises(SheetPlanProblem, match="Test 'WGS' has no test profile."):
            _export(_run(_sample("S1")), _wgs()[0], [])

    def test_a_problem_is_a_value_error(self):
        assert issubclass(SheetPlanProblem, ValueError)


class TestTheFingerprint:
    def test_another_fingerprint_stops_it(self):
        with pytest.raises(SheetPlanChanged) as exc:
            _export(_run(_sample("S1")), *_wgs(), plan_fingerprint="not-the-one")
        assert str(exc.value) == PROFILES_CHANGED == (
            "The profiles changed while the exports were being generated, so the Sample Sheet "
            "would not match what was checked. The run is still a Draft. Mark it Ready again.")

    def test_the_fingerprint_the_checks_passed_writes(self):
        run = _run(_sample("S1"))
        apps, tests = _wgs()
        test_repo, app_repo = _repos(apps, tests)
        fingerprint = plan_sheet(run, test_repo, app_repo, 8).fingerprint
        sheet = SampleSheetV2Exporter.export(run, test_repo, app_repo,
                                             plan_fingerprint=fingerprint)
        assert "[BCLConvert_Data]" in sheet
