"""No v1 sheet when it cannot carry the settings the checks used (spec
2026-10-05 group A3, §3): a v1 sheet has one pair of mismatch numbers for the
whole run, no OverrideCycles, and a Lane column only when some sample has
lanes."""

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.models.validation import ValidationSeverity
from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter
from seqsetup.services.validation import ValidationService, clear_validation_cache

from .test_sheet_plan import BCL_FIELDS, _app, _dragen, _repos, _wgs

RC = RunCycles(151, 151, 10, 10)


def _sample(sample_id="S1", i7="ACGTACGTAC", i5="TTGGCCAATT", lanes=(1,), **fields) -> Sample:
    sample = Sample(sample_id=sample_id, test_id="WGS", test_version="1", lanes=list(lanes))
    if i5 is None:
        sample.assign_index1(Index(name=f"{sample_id}7", sequence=i7, index_type=IndexType.I7))
    else:
        sample.index_pair = IndexPair(
            id=f"p{sample_id}", name=f"p{sample_id}",
            index1=Index(name=f"{sample_id}7", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"{sample_id}5", sequence=i5, index_type=IndexType.I5))
    for name, value in fields.items():
        setattr(sample, name, value)
    return sample


def _run(*samples, platform=InstrumentPlatform.MISEQ, cycles=RC) -> SequencingRun:
    flowcell = {InstrumentPlatform.MISEQ: "v3", InstrumentPlatform.NOVASEQ_6000: "S4",
                InstrumentPlatform.NOVASEQ_X: "10B"}[platform]
    return SequencingRun(run_name="V1", instrument_platform=platform, flowcell_type=flowcell,
                         run_cycles=cycles, samples=list(samples))


class TestTheReasons:
    def test_a_plain_run_has_none(self):
        assert SampleSheetV1Exporter.withheld(_run(_sample())) == ("", [])

    def test_a_shortened_index_masked_after_it_stays(self):
        # I8N2: bcl2fastq uses the shortened sequence (Illumina's comparison):
        # the v1 sheet has the index at 8 bases and no OverrideCycles.
        run = _run(_sample(i7="ACGTACGT", i5="TTGGCCAA"))
        assert SampleSheetV1Exporter.withheld(run) == ("", [])
        lines = SampleSheetV1Exporter.export(run).splitlines()
        header = lines[lines.index("[Data]") + 1].split(",")
        row = dict(zip(header, lines[lines.index("[Data]") + 2].split(",")))
        assert (row["index"], row["index2"]) == ("ACGTACGT", "TTGGCCAA")
        assert not any("OverrideCycles" in line for line in lines)

    def test_its_own_mismatch_number(self):
        run = _run(_sample(barcode_mismatches_index1=0), _sample("S2", i7="TGCATGCAAC"))
        assert SampleSheetV1Exporter.withheld(run) == (
            "S1 were checked with mismatch numbers other than the run's (i7 1, i5 1), which a "
            "v1 sheet writes", ["S1"])

    def test_the_numbers_the_checks_used(self):
        # A profile's Data default 0 for a cleared sample: checked at 0, v1 writes 1.
        sample = _sample(barcode_mismatches_index1=None)
        text, names = SampleSheetV1Exporter.withheld(_run(sample), {(sample.id, 1): 0})
        assert names == ["S1"] and text.startswith("S1 were checked with mismatch numbers")

    def test_a_number_for_an_index_the_sample_lacks_does_not_count(self):
        sample = _sample(i5=None, barcode_mismatches_index2=0)
        assert SampleSheetV1Exporter.withheld(
            _run(sample, cycles=RunCycles(151, 151, 10, 0))) == ("", [])

    def test_a_typed_override_cycles(self):
        run = _run(_sample(override_cycles="Y151;I10;I10;Y150N1"))
        assert SampleSheetV1Exporter.withheld(run) == (
            "S1 have OverrideCycles a v1 sheet cannot hold", ["S1"])

    def test_a_typed_value_equal_to_the_plain_one_is_fine(self):
        assert SampleSheetV1Exporter.withheld(
            _run(_sample(override_cycles="y151;i10;i10;y151"))) == ("", [])

    def test_umi_reads(self):
        run = _run(_sample(read1_override_pattern="U8Y*"))
        assert SampleSheetV1Exporter.withheld(run)[0] == "S1 have OverrideCycles a v1 sheet cannot hold"

    def test_no_lanes_beside_samples_with_lanes(self):
        run = _run(_sample(lanes=()), _sample("S2", i7="TGCATGCAAC"),
                   platform=InstrumentPlatform.NOVASEQ_6000)
        assert SampleSheetV1Exporter.withheld(run) == (
            "S1 have no lanes picked while other samples do", ["S1"])

    def test_several_reasons_and_more_than_five_samples(self):
        i7s = ["ACGTACGTAC", "TGCATGCAAC", "GGGGCCCCAA", "CCCCGGGGTT", "ATATATATAT",
               "CGCGCGCGCG"]
        samples = [_sample(f"S{n}", i7=i7, barcode_mismatches_index2=0)
                   for n, i7 in enumerate(i7s, start=1)]
        samples[0].override_cycles = "Y151;I10;I10;Y150N1"
        text, names = SampleSheetV1Exporter.withheld(_run(*samples))
        assert text == (
            "S1, S2, S3, S4, S5, and 1 more were checked with mismatch numbers other than the "
            "run's (i7 1, i5 1), which a v1 sheet writes; S1 have OverrideCycles a v1 sheet "
            "cannot hold")
        assert names == ["S1", "S2", "S3", "S4", "S5", "S6"]


class TestTheWarning:
    """The validation page warns before Mark Ready, on instruments with a v1
    sheet; Mark Ready is not stopped."""

    def _validate(self, run, *repos):
        clear_validation_cache()
        if repos:
            return ValidationService.validate_run(run, test_profile_repo=repos[0],
                                                  app_profile_repo=repos[1])
        return ValidationService.validate_run(run)

    def test_the_message(self):
        result = self._validate(_run(_sample(barcode_mismatches_index1=0)))
        (warning,) = [e for e in result.configuration_errors if e.category == "no_v1_sheet"]
        assert warning.severity == ValidationSeverity.WARNING
        assert warning.message == (
            "No v1 sheet will be made for this run: S1 were checked with mismatch numbers other "
            "than the run's (i7 1, i5 1), which a v1 sheet writes. A v1 sheet has one pair of "
            "mismatch numbers for the whole run and no OverrideCycles. The v2 sheet is made as "
            "usual.")
        assert warning.sample_names == ["S1"]
        assert result.v1_sheet_withheld == (
            "S1 were checked with mismatch numbers other than the run's (i7 1, i5 1), which a "
            "v1 sheet writes")

    def test_with_the_profiles_the_checks_numbers(self):
        profile = _app("BCLX", data={"BarcodeMismatchesIndex1": 0, "BarcodeMismatchesIndex2": 1})
        sample = _sample(barcode_mismatches_index1=None)
        result = self._validate(_run(sample), *_repos([profile, _dragen("GermX")], _wgs()[1]))
        assert result.v1_sheet_withheld.startswith("S1 were checked with mismatch numbers")

    def test_a_settings_only_profile_with_2(self):
        profile = _app("BCLX", settings={"SoftwareVersion": "4.3.6", "BarcodeMismatchesIndex1": 2,
                                         "BarcodeMismatchesIndex2": 2},
                       fields=BCL_FIELDS[:5], data={})
        result = self._validate(_run(_sample()), *_repos([profile, _dragen("GermX")], _wgs()[1]))
        assert result.v1_sheet_withheld.startswith("S1 were checked with mismatch numbers")

    def test_none_on_an_instrument_without_a_v1_sheet(self):
        result = self._validate(_run(_sample(barcode_mismatches_index1=0),
                                     platform=InstrumentPlatform.NOVASEQ_X))
        assert result.v1_sheet_withheld == ""
        assert [e for e in result.configuration_errors if e.category == "no_v1_sheet"] == []
