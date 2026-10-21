"""Two tests of one TestType and version, each with its own application
profiles: each sample's rows go to its own test's sections of the Sample
Sheet (the user's word, 2026-10-21; docs/design/2026-10-21-tests-by-name-design.md).
Real repositories on mongomock, so the lookup is the stored one."""

import mongomock

from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.repositories.application_profile_repo import ApplicationProfileRepository
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter


def _app(name):
    return ApplicationProfile(name=name, version="1.0.0", application_type="Dragen",
                              application_name=name, settings={"SoftwareVersion": "4.3.6"},
                              data_fields=["Sample_ID"], data={})


BCL = ApplicationProfile(name="BCLConvertNextera", version="1.0.0", application_type="Dragen",
                         application_name="BCLConvert", settings={"SoftwareVersion": "4.3.6"},
                         data_fields=["Lane", "Sample_ID", "Index", "Index2"], data={})


def _test(name, app):
    # Imported here: a module-level TestProfile would be collected by pytest.
    from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
    return TestProfile(test_type="WGS", test_name=name, version="1.0.0",
                       source_file=f"{name}.yaml", application_profiles=[
                           ApplicationProfileReference(profile_name="BCLConvertNextera",
                                                       profile_version="~=1.0"),
                           ApplicationProfileReference(profile_name=app, profile_version="~=1.0")])


def _sample(sample_id, test, i7, i5):
    return Sample(sample_id=sample_id, test_id=test, test_version="1", lanes=[1],
                  index_pair=IndexPair(
                      id=f"p_{sample_id}", name=f"p_{sample_id}",
                      index1=Index(name=f"i7_{sample_id}", sequence=i7, index_type=IndexType.I7),
                      index2=Index(name=f"i5_{sample_id}", sequence=i5, index_type=IndexType.I5)))


def _section(output, name):
    tail = output[output.index(f"[{name}]") + len(name) + 2:]
    end = tail.find("\n[")
    return tail if end == -1 else tail[:end]


class TestEachSampleGetsItsOwnTestsApplications:

    def test_two_tests_of_one_type_and_version(self):
        from seqsetup.repositories.test_profile_repo import TestProfileRepository
        db = mongomock.MongoClient().db
        apps, tests = ApplicationProfileRepository(db), TestProfileRepository(db)
        apps.save(BCL)
        apps.save(_app("DragenGermline"))
        apps.save(_app("DragenRna"))
        tests.save(_test("WGSRareDisease_1", "DragenGermline"))
        tests.save(_test("WGSRareDiseaseResearch_1", "DragenRna"))
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8), samples=[
                _sample("S_CLIN", "WGSRareDisease_1", "ATTACTCG", "TATAGCCT"),
                _sample("S_RES", "WGSRareDiseaseResearch_1", "TCCGGAGA", "ATAGAGGC")])

        output = SampleSheetV2Exporter.export(run, tests, apps)

        bcl = _section(output, "BCLConvert_Data")
        assert "S_CLIN" in bcl and "S_RES" in bcl, output
        germline, rna = _section(output, "DragenGermline_Data"), _section(output, "DragenRna_Data")
        assert "S_CLIN" in germline and "S_RES" not in germline, output
        assert "S_RES" in rna and "S_CLIN" not in rna, output
