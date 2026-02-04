"""Generate Illumina SampleSheet v2 format."""

from io import StringIO
from typing import TextIO, Optional, TYPE_CHECKING

from ..data.instruments import (
    get_bclconvert_software_version,
    get_i5_read_orientation,
    get_samplesheet_platform_name,
    get_samplesheet_v2_i5_orientation,
)
from ..models.analysis import AnalysisType, DRAGENPipeline
from ..models.sequencing_run import SequencingRun
from .cycle_calculator import CycleCalculator
from .samplesheet_v1_exporter import _reverse_complement

if TYPE_CHECKING:
    from ..repositories.test_profile_repo import TestProfileRepository
    from ..repositories.application_profile_repo import ApplicationProfileRepository


class SampleSheetV2Exporter:
    """Generate Illumina SampleSheet v2 format for NovaSeq X and MiSeq i100."""

    FILE_FORMAT_VERSION = 2

    @classmethod
    def export(
        cls,
        run: SequencingRun,
        test_profile_repo: Optional["TestProfileRepository"] = None,
        app_profile_repo: Optional["ApplicationProfileRepository"] = None,
    ) -> str:
        """
        Export sequencing run to SampleSheet v2 CSV format.

        Args:
            run: Sequencing run configuration
            test_profile_repo: Optional repo for looking up TestProfiles by test_id
            app_profile_repo: Optional repo for looking up ApplicationProfiles

        Returns:
            SampleSheet v2 content as string
        """
        output = StringIO()

        # [Header] section
        cls._write_header(output, run)

        # [Reads] section
        cls._write_reads(output, run)

        # Application sections (BCLConvert, DRAGEN pipelines, etc.)
        if test_profile_repo and app_profile_repo:
            # Use ApplicationProfiles for all sections including BCLConvert
            cls._write_application_sections_from_profiles(
                output, run, test_profile_repo, app_profile_repo
            )
        else:
            # Fallback to hardcoded defaults when no repos provided
            cls._write_bclconvert_settings(output, run)
            cls._write_bclconvert_data(output, run)
            if cls._has_dragen_analyses(run):
                cls._write_dragen_sections(output, run)

        # Cloud sections (required for IMS compatibility)
        cls._write_cloud_sections(output, run)

        return output.getvalue()

    @classmethod
    def _write_header(cls, output: TextIO, run: SequencingRun):
        """Write [Header] section."""
        output.write("[Header]\n")
        output.write(f"FileFormatVersion,{cls.FILE_FORMAT_VERSION}\n")

        if run.run_name:
            output.write(f"RunName,{cls._escape_csv(run.run_name)}\n")

        if run.run_description:
            output.write(f"RunDescription,{cls._escape_csv(run.run_description)}\n")

        # Get platform name from config (e.g., "NovaSeqXSeries" for "NovaSeq X Series")
        platform_name = get_samplesheet_platform_name(run.instrument_platform)
        output.write(f"InstrumentPlatform,{platform_name}\n")

        # Index orientation - NovaSeq X expects forward i5 in sample sheet
        output.write("IndexOrientation,Forward\n")

        # Include run UUID for linking with extended metadata
        output.write(f"Custom_UUID,{run.id}\n")

        output.write("\n")

    @classmethod
    def _write_reads(cls, output: TextIO, run: SequencingRun):
        """Write [Reads] section."""
        output.write("[Reads]\n")

        if run.run_cycles:
            output.write(f"Read1Cycles,{run.run_cycles.read1_cycles}\n")
            output.write(f"Read2Cycles,{run.run_cycles.read2_cycles}\n")
            output.write(f"Index1Cycles,{run.run_cycles.index1_cycles}\n")
            output.write(f"Index2Cycles,{run.run_cycles.index2_cycles}\n")

        output.write("\n")

    @classmethod
    def _write_bclconvert_settings(cls, output: TextIO, run: SequencingRun):
        """Write [BCLConvert_Settings] section with hardcoded defaults.

        This is a fallback method used when no ApplicationProfile repos are provided.
        When repos are available, use _write_application_sections_from_profiles instead.
        """
        output.write("[BCLConvert_Settings]\n")

        # Use instrument config defaults
        software_version = get_bclconvert_software_version(run.instrument_platform)
        if software_version:
            output.write(f"SoftwareVersion,{software_version}\n")
        output.write("FastqCompressionFormat,gzip\n")

        # Global override cycles (if all samples have same index lengths)
        global_override = CycleCalculator.infer_global_override_cycles(run)
        if global_override:
            global_override = cls._adjust_override_cycles_for_instrument(
                global_override, run
            )
            output.write(f"OverrideCycles,{global_override}\n")

        output.write("\n")

    @classmethod
    def _write_bclconvert_data(cls, output: TextIO, run: SequencingRun):
        """Write [BCLConvert_Data] section."""
        output.write("[BCLConvert_Data]\n")

        # Determine columns based on data
        has_lanes = any(len(s.lanes) > 0 for s in run.samples)
        # Include per-sample OverrideCycles if no global override was set
        has_per_sample_override = CycleCalculator.infer_global_override_cycles(run) is None
        # Include barcode mismatch columns if any sample has custom values
        has_barcode_mismatch = any(
            s.barcode_mismatches_index1 is not None or s.barcode_mismatches_index2 is not None
            for s in run.samples
        )

        # Header row - use capitalized Index/Index2 for IMS compatibility
        columns = []
        if has_lanes:
            columns.append("Lane")
        columns.extend(["Sample_ID", "Index", "Index2"])
        if has_per_sample_override:
            columns.append("OverrideCycles")
        if has_barcode_mismatch:
            columns.extend(["BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"])

        output.write(",".join(columns) + "\n")

        # Determine if i5 needs reverse-complement for BCL Convert
        v2_i5_orientation = get_samplesheet_v2_i5_orientation(run.instrument_platform)
        rc_i5 = v2_i5_orientation == "reverse-complement"

        # Data rows - output one row per sample per lane
        for sample in run.samples:
            # Get i5 sequence, applying RC if BCL Convert expects it
            i5_seq = sample.index2_sequence or ""
            if rc_i5 and i5_seq:
                i5_seq = _reverse_complement(i5_seq)

            # Calculate per-sample override cycles if needed
            override = None
            if has_per_sample_override:
                override = sample.override_cycles
                if not override and sample.index_pair and run.run_cycles:
                    override = CycleCalculator.calculate_override_cycles(
                        sample, run.run_cycles
                    )
                if override:
                    override = cls._adjust_override_cycles_for_instrument(override, run)

            # If sample has specific lanes, output one row per lane
            # If no lanes specified (empty list), output single row without lane
            lanes_to_output = sample.lanes if sample.lanes else [None]

            for lane in lanes_to_output:
                row = []

                if has_lanes:
                    row.append(str(lane) if lane else "")

                row.append(cls._escape_csv(sample.sample_id))
                row.append(sample.index1_sequence or "")
                row.append(i5_seq)

                if has_per_sample_override:
                    row.append(override or "")

                if has_barcode_mismatch:
                    # Use sample-specific values or fall back to run defaults
                    mm1 = sample.barcode_mismatches_index1 if sample.barcode_mismatches_index1 is not None else run.barcode_mismatches_index1
                    mm2 = sample.barcode_mismatches_index2 if sample.barcode_mismatches_index2 is not None else run.barcode_mismatches_index2
                    row.append(str(mm1))
                    row.append(str(mm2))

                output.write(",".join(row) + "\n")

        output.write("\n")

    @classmethod
    def _has_dragen_analyses(cls, run: SequencingRun) -> bool:
        """Check if run has any DRAGEN onboard analyses."""
        return any(a.analysis_type == AnalysisType.DRAGEN_ONBOARD for a in run.analyses)

    @classmethod
    def _write_dragen_sections(cls, output: TextIO, run: SequencingRun):
        """Write DRAGEN-specific sections for onboard analyses."""
        dragen_analyses = [
            a for a in run.analyses if a.analysis_type == AnalysisType.DRAGEN_ONBOARD
        ]

        for analysis in dragen_analyses:
            if analysis.dragen_pipeline == DRAGENPipeline.GERMLINE:
                cls._write_dragen_germline(output, analysis)
            elif analysis.dragen_pipeline == DRAGENPipeline.SOMATIC:
                cls._write_dragen_somatic(output, analysis)
            elif analysis.dragen_pipeline == DRAGENPipeline.RNA:
                cls._write_dragen_rna(output, analysis)

    @classmethod
    def _write_dragen_germline(cls, output: TextIO, analysis):
        """Write DRAGEN Germline settings and data sections."""
        output.write("[DragenGermline_Settings]\n")

        if analysis.reference_genome:
            output.write(f"ReferenceGenomeDir,{analysis.reference_genome}\n")

        output.write("MapAlignOutFormat,cram\n")
        output.write("\n")

        output.write("[DragenGermline_Data]\n")
        output.write("Sample_ID\n")
        for sample_id in analysis.sample_ids:
            output.write(f"{sample_id}\n")
        output.write("\n")

    @classmethod
    def _write_dragen_somatic(cls, output: TextIO, analysis):
        """Write DRAGEN Somatic settings and data sections."""
        output.write("[DragenSomatic_Settings]\n")

        if analysis.reference_genome:
            output.write(f"ReferenceGenomeDir,{analysis.reference_genome}\n")

        output.write("\n")

        output.write("[DragenSomatic_Data]\n")
        output.write("Sample_ID\n")
        for sample_id in analysis.sample_ids:
            output.write(f"{sample_id}\n")
        output.write("\n")

    @classmethod
    def _write_dragen_rna(cls, output: TextIO, analysis):
        """Write DRAGEN RNA settings and data sections."""
        output.write("[DragenRNA_Settings]\n")

        if analysis.reference_genome:
            output.write(f"ReferenceGenomeDir,{analysis.reference_genome}\n")

        output.write("\n")

        output.write("[DragenRNA_Data]\n")
        output.write("Sample_ID\n")
        for sample_id in analysis.sample_ids:
            output.write(f"{sample_id}\n")
        output.write("\n")

    @classmethod
    def _adjust_override_cycles_for_instrument(
        cls, override_cycles: str, run: SequencingRun
    ) -> str:
        """Adjust override cycles for instrument i5 read orientation.

        Override cycles are always stored in forward orientation. For instruments
        that read i5 in reverse-complement, the Index2 segment (3rd part) must
        be reversed before writing to the samplesheet.

        Args:
            override_cycles: Full override cycles string (e.g., "Y151;I8N2;I8N2;Y151")
            run: Sequencing run (provides instrument platform)

        Returns:
            Adjusted override cycles string
        """
        orientation = get_i5_read_orientation(run.instrument_platform)
        if orientation != "reverse-complement":
            return override_cycles

        parts = override_cycles.split(";")
        if len(parts) != 4:
            return override_cycles

        # Reverse the Index2 segment (3rd part, index 2)
        parts[2] = CycleCalculator.reverse_override_segment(parts[2])
        return ";".join(parts)

    @classmethod
    def _escape_csv(cls, value: str) -> str:
        """Escape a value for CSV output."""
        if "," in value or '"' in value or "\n" in value:
            return '"' + value.replace('"', '""') + '"'
        return value

    @classmethod
    def _write_application_sections_from_profiles(
        cls,
        output: TextIO,
        run: SequencingRun,
        test_profile_repo: "TestProfileRepository",
        app_profile_repo: "ApplicationProfileRepository",
    ):
        """
        Write application sections based on ApplicationProfile definitions.

        Groups samples by test_id, resolves TestProfile -> ApplicationProfiles,
        and generates [AppName_Settings] and [AppName_Data] sections for all
        applications including BCLConvert and DRAGEN pipelines.
        """
        # Group samples by test_id
        samples_by_test: dict[str, list] = {}
        for sample in run.samples:
            if sample.test_id:
                if sample.test_id not in samples_by_test:
                    samples_by_test[sample.test_id] = []
                samples_by_test[sample.test_id].append(sample)

        if not samples_by_test:
            return

        # Track which application profiles we've already written
        written_profiles: set[tuple[str, str]] = set()

        # For each test type, get application profiles and write sections
        for test_id, samples in samples_by_test.items():
            # Look up TestProfile by test_type
            test_profile = test_profile_repo.get_by_test_type(test_id)
            if not test_profile:
                continue

            # Resolve each ApplicationProfile reference
            for app_ref in test_profile.application_profiles:
                profile_key = (app_ref.profile_name, app_ref.profile_version)

                # Skip if already written
                if profile_key in written_profiles:
                    continue

                # Look up ApplicationProfile
                app_profile = app_profile_repo.get_by_name_version(
                    app_ref.profile_name, app_ref.profile_version
                )
                if not app_profile:
                    continue

                # Write settings and data sections
                cls._write_application_profile_section(output, app_profile, samples, run)
                written_profiles.add(profile_key)

    @classmethod
    def _write_application_profile_section(
        cls,
        output: TextIO,
        profile,
        samples: list,
        run: Optional[SequencingRun] = None,
    ):
        """Write [AppName_Settings] and [AppName_Data] sections from profile."""
        app_name = profile.application_name

        # Write Settings section
        output.write(f"[{app_name}_Settings]\n")
        for key, value in profile.settings.items():
            output.write(f"{key},{value}\n")
        output.write("\n")

        # Write Data section
        output.write(f"[{app_name}_Data]\n")

        # Get data fields from profile, filtering out fields we handle specially
        data_fields = profile.data_fields or list(profile.data.keys())

        # Write header row
        output.write(",".join(data_fields) + "\n")

        # Write data rows for each sample
        for sample in samples:
            row = []
            for field in data_fields:
                if field == "Sample_ID":
                    row.append(cls._escape_csv(sample.sample_id))
                elif field == "Lane":
                    # Use first lane if available
                    row.append(str(sample.lanes[0]) if sample.lanes else "")
                elif field == "Index":
                    # i7 index sequence
                    row.append(sample.index1_sequence or "")
                elif field == "Index2":
                    # i5 index sequence, with RC handling for instrument
                    i5 = sample.index2_sequence or ""
                    if i5 and run:
                        v2_orient = get_samplesheet_v2_i5_orientation(run.instrument_platform)
                        if v2_orient == "reverse-complement":
                            i5 = _reverse_complement(i5)
                    row.append(i5)
                elif field in profile.translate:
                    # Handle translated fields (e.g., IndexI7 -> Index)
                    original = profile.translate[field]
                    if original == "Index":
                        row.append(sample.index1_sequence or "")
                    elif original == "Index2":
                        i5 = sample.index2_sequence or ""
                        if i5 and run:
                            v2_orient = get_samplesheet_v2_i5_orientation(run.instrument_platform)
                            if v2_orient == "reverse-complement":
                                i5 = _reverse_complement(i5)
                        row.append(i5)
                    else:
                        row.append(str(profile.data.get(field, "")))
                elif field == "BarcodeMismatchesIndex1":
                    val = sample.barcode_mismatches_index1
                    row.append(str(val) if val is not None else str(profile.data.get(field, "")))
                elif field == "BarcodeMismatchesIndex2":
                    val = sample.barcode_mismatches_index2
                    row.append(str(val) if val is not None else str(profile.data.get(field, "")))
                elif field == "OverrideCycles":
                    # Use sample's override cycles, or calculate from index lengths
                    oc = sample.override_cycles
                    if not oc and sample.index_pair and run and run.run_cycles:
                        oc = CycleCalculator.calculate_override_cycles(sample, run.run_cycles)
                    if oc and run:
                        oc = cls._adjust_override_cycles_for_instrument(oc, run)
                    row.append(oc or "")
                else:
                    # Use default value from profile data
                    row.append(str(profile.data.get(field, "")))
            output.write(",".join(row) + "\n")

        output.write("\n")

    @classmethod
    def _write_cloud_sections(cls, output: TextIO, run: SequencingRun):
        """Write [Cloud_Settings] and [Cloud_Data] sections for IMS compatibility."""
        # Cloud_Settings - minimal section with generated version
        output.write("[Cloud_Settings]\n")
        output.write("GeneratedVersion,2.7.0\n")
        output.write("\n")

        # Cloud_Data - sample metadata
        output.write("[Cloud_Data]\n")
        output.write("Sample_ID,ProjectName,LibraryName\n")

        project_name = run.run_name or "SeqSetup_Run"
        for sample in run.samples:
            # LibraryName follows pattern: SampleID_Index1_Index2
            i7 = sample.index1_sequence or ""
            i5 = sample.index2_sequence or ""
            library_name = f"{sample.sample_id}_{i7}_{i5}" if i7 and i5 else sample.sample_id

            row = [
                cls._escape_csv(sample.sample_id),
                cls._escape_csv(project_name),
                cls._escape_csv(library_name),
            ]
            output.write(",".join(row) + "\n")

        output.write("\n")
