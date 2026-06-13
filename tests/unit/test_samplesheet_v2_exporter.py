"""Tests for SampleSheet v2 exporter."""

import pytest

from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter


class TestSampleSheetV2Exporter:
    """Tests for SampleSheetV2Exporter."""

    def test_export_header_section(self, sample_run):
        """Test [Header] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[Header]" in output
        assert "FileFormatVersion,2" in output
        assert "RunName,TestRun_001" in output
        assert "InstrumentPlatform,NovaSeqXSeries" in output

    def test_export_reads_section(self, sample_run):
        """Test [Reads] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[Reads]" in output
        assert "Read1Cycles,151" in output
        assert "Read2Cycles,151" in output
        assert "Index1Cycles,10" in output
        assert "Index2Cycles,10" in output

    def test_export_bclconvert_settings(self, sample_run):
        """Test [BCLConvert_Settings] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[BCLConvert_Settings]" in output
        assert "FastqCompressionFormat,gzip" in output
        # Barcode mismatches are in BCLConvert_Data, not Settings (only when custom values)

    def test_export_bclconvert_data(self, sample_run):
        """Test [BCLConvert_Data] section output."""
        output = SampleSheetV2Exporter.export(sample_run)

        assert "[BCLConvert_Data]" in output
        # Column names use capitalized Index/Index2 for IMS compatibility
        # Sample_Project is in Cloud_Data section as ProjectName
        assert "Sample_ID,Index,Index2" in output
        assert "Sample_001,ATTACTCG,TATAGCCT" in output

    def test_export_override_cycles_global(self, sample_run):
        """Test global OverrideCycles when all indexes same length.

        Per Illumina BCL Convert: the OverrideCycles Index2 segment matches
        the orientation of the i5 sequence as it appears in the sample
        sheet (not the physical-read orientation). NovaSeq X sample sheets
        carry i5 in FORWARD orientation, so the Index2 token stays forward
        (``I8N2``), not reversed.
        """
        output = SampleSheetV2Exporter.export(sample_run)
        assert "OverrideCycles,Y151;I8N2;I8N2;Y151" in output

    def test_export_override_cycles_global_forward_instrument(self):
        """Test global OverrideCycles for a forward-orientation instrument."""
        run = SequencingRun(
            run_name="MiSeq Run",
            instrument_platform=InstrumentPlatform.MISEQ_I100,
            flowcell_type="25M",
            run_cycles=RunCycles(150, 150, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1",
                        name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )

        output = SampleSheetV2Exporter.export(run)

        # MiSeq i100 sample sheet carries i5 in forward orientation; Index2 forward too.
        assert "OverrideCycles,Y150;I8N2;I8N2;Y150" in output

    def test_export_override_cycles_global_rc_instrument(self):
        """For instruments whose sample sheet specifies i5 in reverse-complement
        orientation (e.g. NextSeq 500/550, NovaSeq 6000), the OverrideCycles
        Index2 token must also be reversed — N at the beginning per Illumina
        BCL Convert guidance.
        """
        run = SequencingRun(
            run_name="NextSeq Run",
            instrument_platform=InstrumentPlatform.NEXTSEQ_500_550,
            flowcell_type="High",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # NextSeq 500/550 sample sheet carries i5 in RC → Index2 token reversed.
        assert "OverrideCycles,Y151;I8N2;N2I8;Y151" in output

    def test_adjust_override_cycles_comma_separator_on_rc_instrument(self):
        """A legacy comma-separated OverrideCycles must still get its Index2
        token RC-adjusted on an RC instrument. Previously split(';') saw one
        part, skipped the adjustment, and left Index2 desynced from the RC'd i5."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NEXTSEQ_500_550,
            flowcell_type="High",
            run_cycles=RunCycles(151, 151, 10, 10),
        )
        result = SampleSheetV2Exporter._adjust_override_cycles_for_instrument(
            "Y151,I8N2,I8N2,Y151", run
        )
        assert result == "Y151;I8N2;N2I8;Y151"

    def test_comma_override_normalized_to_semicolon_on_forward_instrument(self):
        """BCL Convert v2 uses ';' as the OverrideCycles separator; a legacy
        comma-form override must be normalized to ';' on FORWARD instruments too,
        not emitted with literal commas the sequencer can't parse."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,  # forward orientation
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
        )
        result = SampleSheetV2Exporter._adjust_override_cycles_for_instrument(
            "Y151,I8N2,I8N2,Y151", run
        )
        assert result == "Y151;I8N2;I8N2;Y151"  # commas->';', no RC flip (forward)

    def test_single_index_sample_gets_computed_override_not_blank(self):
        """In a run that forces per-sample OverrideCycles, a single-index sample
        (index1 only, no index_pair, no explicit override) must get a COMPUTED
        OverrideCycles, not a blank cell — the fallback now keys on has_index."""
        run = SequencingRun(
            run_name="Mixed",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,  # forward, no RC noise
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(sample_id="DUAL", index_pair=IndexPair(
                    id="p1", name="p1",
                    index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                    index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5))),
                Sample(sample_id="SINGLE", index1=Index(
                    name="j7", sequence="GGGGCCCC", index_type=IndexType.I7)),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # SINGLE: index1 8bp -> I8N2; absent index2 over 10 cycles -> N10.
        assert "Y151;I8N2;N10;Y151" in output

    def test_export_bclconvert_runtime_settings_emitted(self, sample_run):
        """no_lane_splitting / create_fastq_for_index_reads / adapter_behavior
        on the run model must appear in [BCLConvert_Settings]; silent drop
        would mean a clinician's toggle in the UI never reaches BCL Convert.
        """
        sample_run.no_lane_splitting = True
        sample_run.create_fastq_for_index_reads = True
        sample_run.adapter_behavior = "mask"
        output = SampleSheetV2Exporter.export(sample_run)
        assert "NoLaneSplitting,true" in output
        assert "CreateFastqForIndexReads,1" in output
        assert "AdapterBehavior,mask" in output

    def test_export_bclconvert_default_lane_split_emitted_as_false(self, sample_run):
        """Defaults still go on the wire so the value is deterministic — BCL
        Convert would otherwise apply its own default and the operator can't
        tell from the artifact what the run was configured for."""
        output = SampleSheetV2Exporter.export(sample_run)
        assert "NoLaneSplitting,false" in output
        assert "CreateFastqForIndexReads,0" in output
        # AdapterBehavior is omitted when "trim" (default) — see
        # _format_bclconvert_run_settings docstring.
        assert "AdapterBehavior" not in output

    def test_export_override_cycles_per_sample(self, sample_run):
        """Test per-sample OverrideCycles when indexes differ."""
        # Add sample with different index length
        sample_run.add_sample(
            Sample(
                sample_id="Sample_002",
                index_pair=IndexPair(
                    id="diff",
                    name="diff",
                    index1=Index(
                        name="i7", sequence="ATCGATCGATCG", index_type=IndexType.I7
                    ),
                    index2=Index(
                        name="i5", sequence="GCTAGCTACCGG", index_type=IndexType.I5
                    ),
                ),
            )
        )

        output = SampleSheetV2Exporter.export(sample_run)

        # Should have per-sample override cycles column
        assert "Sample_ID,Index,Index2,OverrideCycles" in output

    def test_export_with_lanes(self, sample_run):
        """Test export with lane assignments."""
        sample_run.samples[0].lanes = [1]

        output = SampleSheetV2Exporter.export(sample_run)

        # Should have Lane column
        assert "Lane,Sample_ID" in output
        assert "1,Sample_001" in output

    def test_export_with_dragen_germline(self, sample_run, sample_analysis):
        """Test export with DRAGEN Germline analysis."""
        sample_analysis.sample_ids = [sample_run.samples[0].sample_id]
        sample_run.add_analysis(sample_analysis)

        output = SampleSheetV2Exporter.export(sample_run)

        assert "[DragenGermline_Settings]" in output
        assert "ReferenceGenomeDir,hg38" in output
        assert "[DragenGermline_Data]" in output
        assert "Sample_001" in output

    def test_export_escapes_csv_values(self):
        """Test that values with commas are properly escaped."""
        run = SequencingRun(
            run_name="Run, with comma",
            run_cycles=RunCycles(151, 151, 10, 10),
        )

        output = SampleSheetV2Exporter.export(run)

        assert '"Run, with comma"' in output

    def test_escape_csv_quotes_lone_cr(self):
        """A lone CR (Mac-style line ending) must be quoted, not written raw."""
        assert SampleSheetV2Exporter._escape_csv("foo\rbar") == '"foo\rbar"'

    def test_escape_csv_quotes_crlf(self):
        """A CRLF sequence must be quoted (the \\n already triggers, but the \\r should be preserved inside quotes)."""
        assert SampleSheetV2Exporter._escape_csv("foo\r\nbar") == '"foo\r\nbar"'

    def test_export_normalizes_legacy_comma_override_to_semicolon(self):
        """A legacy comma-separated override_cycles is normalized to the BCL
        Convert ';' separator on export (regardless of instrument), so it is a
        single CSV cell with the correct separator — not emitted with literal
        commas (which BCL Convert can't parse and which would also split the
        row). Per-sample OverrideCycles column is emitted only when global
        inference fails (samples disagree on effective index lengths), so two
        samples with different index lengths force the per-sample path.
        """
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    override_cycles="Y151,I8,I8,Y151",  # legacy comma-separated form
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),  # 8 bp
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
                Sample(
                    sample_id="S2",
                    index_pair=IndexPair(
                        id="p2", name="p2",
                        index1=Index(name="i7b", sequence="TCCGGAGAGG", index_type=IndexType.I7),  # 10 bp
                        index2=Index(name="i5b", sequence="ATAGAGGCAA", index_type=IndexType.I5),
                    ),
                ),
            ],
        )

        output = SampleSheetV2Exporter.export(run)
        # Normalized to ';' (BCL Convert separator); no literal comma remains, so
        # no CSV-quoting is needed and the row keeps the right column count.
        assert "Y151;I8;I8;Y151" in output
        assert '"Y151,I8,I8,Y151"' not in output

    def test_export_escapes_reference_genome_with_comma(self):
        """analysis.reference_genome with a comma must be quoted in DRAGEN sections."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
            analyses=[
                Analysis(
                    name="malicious",
                    analysis_type=AnalysisType.DRAGEN_ONBOARD,
                    dragen_pipeline=DRAGENPipeline.GERMLINE,
                    reference_genome="hg38,injected",
                    sample_ids=["S1"],
                ),
            ],
        )

        output = SampleSheetV2Exporter.export(run)
        assert '"hg38,injected"' in output

    def test_export_escapes_application_profile_data_value_with_comma(self):
        """profile.data fallback values must be CSV-quoted in the Data section.

        Admin-provided default values in an ApplicationProfile's ``data`` dict
        flow into BCLConvert_Data rows for fields the sample doesn't override.
        A comma in any such value would shift columns downstream."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[
                Sample(
                    sample_id="S1",
                    test_id="WGS",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        app_profile = ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="BclConvert",
            application_name="BCLConvert",
            settings={},
            data_fields=["Sample_ID", "Index", "Index2", "ExtraField"],
            data={"ExtraField": "value,with,commas"},
        )
        tp = TestProfile(
            test_type="WGS", test_name="WGS", version="1.0.0",
            application_profiles=[ApplicationProfileReference(profile_name="BCLConvertNextera", profile_version="1.0.0")],
        )
        test_profile_repo = _StubTestProfileRepo({"WGS": tp})
        app_profile_repo = _StubAppProfileRepo({("BCLConvertNextera", "1.0.0"): app_profile})

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)
        assert '"value,with,commas"' in output

    def test_export_escapes_application_profile_setting_with_comma(self):
        """profile.settings keys/values with commas must be CSV-quoted in the Settings section."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[
                Sample(
                    sample_id="S1",
                    test_id="WGS",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        app_profile = ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="BclConvert",
            application_name="BCLConvert",
            settings={"SoftwareVersion": "4.3,injected"},
            data_fields=["Sample_ID", "Index", "Index2"],
            data={},
        )
        tp = TestProfile(
            test_type="WGS",
            test_name="WGS",
            version="1.0.0",
            application_profiles=[
                ApplicationProfileReference(profile_name="BCLConvertNextera", profile_version="1.0.0"),
            ],
        )
        test_profile_repo = _StubTestProfileRepo({"WGS": tp})
        app_profile_repo = _StubAppProfileRepo({("BCLConvertNextera", "1.0.0"): app_profile})

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)
        # The value contained a comma — must be quoted so it stays a single CSV field.
        assert '"4.3,injected"' in output

    def test_export_empty_run(self):
        """Test exporting run with no samples."""
        run = SequencingRun(
            run_name="Empty",
            run_cycles=RunCycles(151, 151, 10, 10),
        )

        output = SampleSheetV2Exporter.export(run)

        # Should still have sections
        assert "[Header]" in output
        assert "[BCLConvert_Data]" in output

    def test_export_miseq_platform(self):
        """Test export for MiSeq i100 platform."""
        run = SequencingRun(
            run_name="MiSeq Run",
            instrument_platform=InstrumentPlatform.MISEQ_I100,
            flowcell_type="25M",
            run_cycles=RunCycles(150, 150, 10, 10),
        )

        output = SampleSheetV2Exporter.export(run)

        # samplesheet_name for MiSeq i100 is "MiSeqi100Series"
        assert "InstrumentPlatform,MiSeqi100Series" in output

    def test_export_novaseq_x_i5_forward(self):
        """NovaSeq X: BCL Convert expects i5 in forward orientation."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # i5 should be forward (as stored) for NovaSeq X
        assert "S1,ATTACTCG,TATAGCCT," in output

    def test_export_novaseq_6000_i5_reverse_complement(self):
        """NovaSeq 6000: BCL Convert expects i5 reverse-complemented."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_6000,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # TATAGCCT reverse-complemented is AGGCTATA
        assert "S1,ATTACTCG,AGGCTATA" in output
        # Check BCLConvert_Data section only (not Cloud_Data where forward i5 appears in LibraryName)
        bclconvert_data = output.split("[BCLConvert_Data]")[1].split("[Cloud_")[0]
        assert "TATAGCCT" not in bclconvert_data

    def test_export_nextseq_500_i5_reverse_complement(self):
        """NextSeq 500/550: BCL Convert expects i5 reverse-complemented."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NEXTSEQ_500_550,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # TATAGCCT reverse-complemented is AGGCTATA
        assert "S1,ATTACTCG,AGGCTATA," in output

    def test_export_miseq_classic_i5_forward(self):
        """MiSeq (classic): BCL Convert expects i5 in forward orientation."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MISEQ,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # i5 should be forward for MiSeq
        assert "S1,ATTACTCG,TATAGCCT," in output

    def test_export_miniseq_i5_reverse_complement(self):
        """MiniSeq: BCL Convert expects i5 reverse-complemented."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.MINISEQ,
            run_cycles=RunCycles(151, 151, 10, 10),
            samples=[
                Sample(
                    sample_id="S1",
                    index_pair=IndexPair(
                        id="p1", name="p1",
                        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                    ),
                ),
            ],
        )
        output = SampleSheetV2Exporter.export(run)
        # TATAGCCT reverse-complemented is AGGCTATA
        assert "S1,ATTACTCG,AGGCTATA," in output


class _StubTestProfileRepo:
    """In-memory test profile repo keyed by test_type."""

    def __init__(self, profiles_by_test_type: dict):
        self._profiles = profiles_by_test_type

    def get_by_test_type(self, test_type):
        return self._profiles.get(test_type)


class _StubAppProfileRepo:
    """In-memory application profile repo keyed by (name, version)."""

    def __init__(self, profiles_by_key: dict):
        self._profiles = profiles_by_key

    def get_by_name_version(self, name, version):
        return self._profiles.get((name, version))


class TestApplicationSectionsAcrossTestProfiles:
    """When two TestProfiles reference the same ApplicationProfile, samples from
    every referencing test_id must appear in that profile's data section.

    Without this guarantee, the exporter writes the section once with only the
    first test_id's samples and silently drops the rest — they never reach the
    sequencer's demultiplexer.
    """

    def _make_app_profile(self):
        return ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="BclConvert",
            application_name="BCLConvert",
            settings={"SoftwareVersion": "4.3.6"},
            data_fields=["Sample_ID", "Index", "Index2"],
            data={},
        )

    def _make_test_profile(self, test_type):
        return TestProfile(
            test_type=test_type,
            test_name=test_type,
            version="1.0.0",
            application_profiles=[
                ApplicationProfileReference(
                    profile_name="BCLConvertNextera",
                    profile_version="1.0.0",
                ),
            ],
        )

    def _make_sample(self, sample_id, test_id, i7, i5):
        return Sample(
            sample_id=sample_id,
            test_id=test_id,
            index_pair=IndexPair(
                id=f"pair_{sample_id}",
                name=f"pair_{sample_id}",
                index1=Index(name=f"i7_{sample_id}", sequence=i7, index_type=IndexType.I7),
                index2=Index(name=f"i5_{sample_id}", sequence=i5, index_type=IndexType.I5),
            ),
        )

    @staticmethod
    def _extract_section(output: str, section_name: str) -> str:
        """Return the body of [section_name] (everything until the next [Section] or EOF)."""
        marker = f"[{section_name}]"
        start = output.index(marker) + len(marker)
        tail = output[start:]
        # Section ends at the next "[...]" header
        next_idx = tail.find("\n[")
        return tail if next_idx == -1 else tail[:next_idx]

    def test_shared_app_profile_includes_samples_from_every_test_id(self):
        """A sample whose test_id resolves to an already-emitted ApplicationProfile must still appear in that profile's data section."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[
                self._make_sample("S_WGS", "WGS", "ATTACTCG", "TATAGCCT"),
                self._make_sample("S_RNA", "RNA", "TCCGGAGA", "ATAGAGGC"),
            ],
        )
        app_profile = self._make_app_profile()
        test_profile_repo = _StubTestProfileRepo({
            "WGS": self._make_test_profile("WGS"),
            "RNA": self._make_test_profile("RNA"),
        })
        app_profile_repo = _StubAppProfileRepo({
            ("BCLConvertNextera", "1.0.0"): app_profile,
        })

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)
        # Pin the assertions to BCLConvert_Data — both samples also legitimately
        # appear in Cloud_Data, so a global `in output` check would not catch the bug.
        bcl_data = self._extract_section(output, "BCLConvert_Data")
        assert "S_WGS" in bcl_data
        assert "S_RNA" in bcl_data

    def test_shared_app_profile_section_written_only_once(self):
        """The shared section must not be duplicated (header line appears once)."""
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[
                self._make_sample("S_WGS", "WGS", "ATTACTCG", "TATAGCCT"),
                self._make_sample("S_RNA", "RNA", "TCCGGAGA", "ATAGAGGC"),
            ],
        )
        app_profile = self._make_app_profile()
        test_profile_repo = _StubTestProfileRepo({
            "WGS": self._make_test_profile("WGS"),
            "RNA": self._make_test_profile("RNA"),
        })
        app_profile_repo = _StubAppProfileRepo({
            ("BCLConvertNextera", "1.0.0"): app_profile,
        })

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)

        assert output.count("[BCLConvert_Data]") == 1
        assert output.count("[BCLConvert_Settings]") == 1

    def test_single_index_sample_override_cycles_on_profile_export_path(self):
        """The production (profile-driven) export path must compute OverrideCycles
        for a single-index sample (index1 only, no index_pair, no explicit
        override) — not emit a blank cell, which would misroute its reads."""
        app_profile = ApplicationProfile(
            name="BCLConvertNextera",
            version="1.0.0",
            application_type="BclConvert",
            application_name="BCLConvert",
            settings={"SoftwareVersion": "4.3.6"},
            data_fields=["Sample_ID", "OverrideCycles"],
            data={},
        )
        run = SequencingRun(
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
            samples=[Sample(sample_id="S_SINGLE", test_id="WGS", index1=Index(
                name="i7", sequence="ATTACTCG", index_type=IndexType.I7))],
        )
        test_profile_repo = _StubTestProfileRepo({"WGS": self._make_test_profile("WGS")})
        app_profile_repo = _StubAppProfileRepo({("BCLConvertNextera", "1.0.0"): app_profile})

        output = SampleSheetV2Exporter.export(run, test_profile_repo, app_profile_repo)
        # index1 8bp over 8 index1 cycles -> I8; absent index2 over 8 -> N8.
        # The single-index sample's OverrideCycles cell must be computed, not blank.
        assert "S_SINGLE,Y151;I8;N8;Y151" in output
