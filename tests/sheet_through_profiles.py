"""The sheet production writes, for a test that only needs one.

SeqSetup has one Sample Sheet v2 writer: the profile-driven one, which
``SampleSheetV2Exporter.export`` reaches whenever it is given the two profile
repositories -- and production always gives it both. A test that exported
without them ran a second writer, with another column order and `1` where
production writes `na`, so it proved nothing about the sheet a laboratory gets
(review TH-1, 2026-10-21). That writer is gone; this module is what the tests
that used it call instead.
"""

from seqsetup.models.analysis import DRAGENPipeline
from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter


class _StubTestProfileRepo:
    """In-memory test profile repo keyed by the sample's test (a TestName)."""

    def __init__(self, profiles_by_test: dict):
        self._profiles = profiles_by_test

    def list_by_test_name(self, test_name):
        profile = self._profiles.get(test_name)
        return [profile] if profile else []


class _StubAppProfileRepo:
    """In-memory application profile repo keyed by (name, version)."""

    def __init__(self, profiles_by_key: dict):
        self._profiles = profiles_by_key

    def get_by_name_version(self, name, version):
        return self._profiles.get((name, version))


# The one BCLConvert profile the tests below write through. SeqSetup has one
# v2 writer, the profile-driven one, and production always reaches it: a test
# that exported with no profile repositories ran a second writer -- another
# column order, and `1` where production writes `na` -- so it proved nothing
# about the sheet a laboratory gets (review TH-1). These fields are the
# shipped BCLConvertNextera profile's, less the two adapter columns it leaves
# empty.
_TEST_NAME = "WGS"
# Which application profile a DRAGEN analysis needs, so a run that carries one
# gets the section the fallback wrote from the analysis itself.
_DRAGEN_APPLICATION = {
    DRAGENPipeline.GERMLINE: "DragenGermline",
    DRAGENPipeline.SOMATIC: "DragenSomatic",
    DRAGENPipeline.RNA: "DragenRna",
    DRAGENPipeline.ENRICHMENT: "DragenEnrichment",
}
_DEFAULT_FIELDS = ["Sample_ID", "Lane", "Index", "Index2", "OverrideCycles",
                   "BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"]


# The shipped BCLConvertNextera profile's own Settings. The writer this
# replaced hard-coded SoftwareVersion and FastqCompressionFormat; production
# writes what the profile says, so the profile says it.
_DEFAULT_SETTINGS = {"SoftwareVersion": "4.3.6", "FastqCompressionFormat": "gzip"}


def _bclconvert_profile(fields=None, settings=None) -> ApplicationProfile:
    return ApplicationProfile(
        name="TestBCLConvert", version="1.0.0", application_type="Dragen",
        application_name="BCLConvert",
        settings=dict(_DEFAULT_SETTINGS) if settings is None else settings,
        data={}, data_fields=list(_DEFAULT_FIELDS if fields is None else fields),
    )


def _repos_for(*profiles):
    """The repositories production reads, holding ``profiles`` under one test."""
    return (
        _StubTestProfileRepo({_TEST_NAME: TestProfile(
            test_type=_TEST_NAME, test_name=_TEST_NAME, version="1.0.0",
            application_profiles=[ApplicationProfileReference(
                profile_name=p.name, profile_version=p.version) for p in profiles])}),
        _StubAppProfileRepo({(p.name, p.version): p for p in profiles}),
    )


def sheet(run, *, fields=None, settings=None, **kw) -> str:
    """The sheet production writes for ``run``: the profile-driven path, with
    one plain BCLConvert profile. Every sample is given the test that profile
    is listed under, which is what the checks require of a Ready run anyway
    (``_validate_samples_have_test_id``).

    The profile carries a Lane column only when the run's samples have lanes,
    as the writer this replaced decided from the data -- a Lane column with a
    sample that has no lane is a refused sheet (``sheet_plan``), which is the
    lab's own rule and not what these tests are about."""
    for sample in run.samples:
        if not sample.test_id:
            sample.test_id = _TEST_NAME
            sample.test_version = "1"
    if fields is None and not any(sample.lanes for sample in run.samples):
        fields = [name for name in _DEFAULT_FIELDS if name != "Lane"]
    profiles = [_bclconvert_profile(fields, settings)]
    for analysis in run.analyses:
        name = _DRAGEN_APPLICATION.get(getattr(analysis, "dragen_pipeline", None))
        if name:
            # The genome comes from the profile, as it does in production:
            # the writer this replaced read it from the Analysis itself.
            profiles.append(ApplicationProfile(
                name=name, version="1.0.0", application_type="Dragen",
                application_name=name, settings={"SoftwareVersion": "4.3.6"},
                data={"ReferenceGenomeDir": "hg38"},
                data_fields=["Sample_ID", "ReferenceGenomeDir"]))
    return SampleSheetV2Exporter.export(run, *_repos_for(*profiles), **kw)


