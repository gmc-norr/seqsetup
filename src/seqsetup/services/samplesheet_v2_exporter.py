"""Generate Illumina SampleSheet v2 format."""

from io import StringIO
from typing import TextIO, Optional, TYPE_CHECKING

from ..data.instruments import (
    get_bclconvert_software_version,
    get_samplesheet_platform_name,
    get_samplesheet_v2_i5_orientation,
)
from ..models.analysis import AnalysisType, DRAGENPipeline
from ..models.sequencing_run import SequencingRun
from .cycle_calculator import CycleCalculator
from .samplesheet_v1_exporter import _PLAIN_IDENTIFIER_RE, _reverse_complement

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

        # Run-level BCL Convert flags carried on the SequencingRun model. Per
        # the Illumina v2 spec these belong in [BCLConvert_Settings]:
        #   NoLaneSplitting,true|false        (concat per-lane FASTQs)
        #   CreateFastqForIndexReads,0|1      (emit FASTQs for index reads)
        #   AdapterBehavior,trim|mask|none    (adapter trimming behaviour)
        # We emit them unconditionally so a toggled value in the model
        # always reaches the demultiplexer — silent drop would diverge
        # operator expectation from sequencer behaviour.
        for line in cls._format_bclconvert_run_settings(run):
            output.write(line)

        # Global override cycles (if all samples have same index lengths)
        global_override = CycleCalculator.infer_global_override_cycles(run)
        if global_override:
            global_override = cls._adjust_override_cycles_for_instrument(
                global_override, run
            )
            output.write(f"OverrideCycles,{global_override}\n")

        output.write("\n")

    @classmethod
    def _format_bclconvert_run_settings(cls, run: SequencingRun) -> list[str]:
        """Render the run-level BCL Convert v2 settings as ``key,value\\n`` lines.

        Returns a list of pre-newline-terminated lines so callers can emit
        them into either the fallback section (above) or a profile-driven
        section (see ``_write_application_profile_section``). Centralising
        the format avoids drift between the two paths.
        """
        adapter = (run.adapter_behavior or "").strip().lower()
        lines: list[str] = [
            f"NoLaneSplitting,{'true' if run.no_lane_splitting else 'false'}\n",
            f"CreateFastqForIndexReads,{1 if run.create_fastq_for_index_reads else 0}\n",
        ]
        # AdapterBehavior is omitted when the model is at its default "trim"
        # to keep the sheet minimal — BCL Convert applies "trim" implicitly.
        # Mask/None must be opted into explicitly.
        if adapter and adapter != "trim":
            lines.append(f"AdapterBehavior,{adapter}\n")
        return lines

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

        # Data rows - output one row per sample per lane
        for sample in run.samples:
            # i5 sequence in sample-sheet orientation (RC applied for
            # instruments where the sample sheet expects RC).
            i5_seq = cls._resolve_i5(sample, run)

            # Calculate per-sample override cycles if needed
            override = None
            if has_per_sample_override:
                override = sample.override_cycles
                if not override and sample.has_index and run.run_cycles:
                    # has_index (not index_pair) so combinatorial/single-index
                    # samples also get a computed OverrideCycles, not a blank cell.
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

                row.append(cls._escape_identifier(sample.sample_id))
                # Escape index sequences too — parity with the profile-driven
                # path. They are model-validated to [ACGTN], but Index has no
                # __setattr__ so a post-construction reassignment could bypass
                # that; escaping defensively keeps the row column count correct.
                row.append(cls._escape_csv(sample.index1_sequence or ""))
                row.append(cls._escape_csv(i5_seq))

                if has_per_sample_override:
                    row.append(cls._escape_csv(override or ""))

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
            output.write(f"ReferenceGenomeDir,{cls._escape_csv(analysis.reference_genome)}\n")

        output.write("MapAlignOutFormat,cram\n")
        output.write("\n")

        output.write("[DragenGermline_Data]\n")
        output.write("Sample_ID\n")
        for sample_id in analysis.sample_ids:
            output.write(f"{cls._escape_identifier(sample_id)}\n")
        output.write("\n")

    @classmethod
    def _write_dragen_somatic(cls, output: TextIO, analysis):
        """Write DRAGEN Somatic settings and data sections."""
        output.write("[DragenSomatic_Settings]\n")

        if analysis.reference_genome:
            output.write(f"ReferenceGenomeDir,{cls._escape_csv(analysis.reference_genome)}\n")

        output.write("\n")

        output.write("[DragenSomatic_Data]\n")
        output.write("Sample_ID\n")
        for sample_id in analysis.sample_ids:
            output.write(f"{cls._escape_identifier(sample_id)}\n")
        output.write("\n")

    @classmethod
    def _write_dragen_rna(cls, output: TextIO, analysis):
        """Write DRAGEN RNA settings and data sections."""
        output.write("[DragenRNA_Settings]\n")

        if analysis.reference_genome:
            output.write(f"ReferenceGenomeDir,{cls._escape_csv(analysis.reference_genome)}\n")

        output.write("\n")

        output.write("[DragenRNA_Data]\n")
        output.write("Sample_ID\n")
        for sample_id in analysis.sample_ids:
            output.write(f"{cls._escape_identifier(sample_id)}\n")
        output.write("\n")

    @classmethod
    def _adjust_override_cycles_for_instrument(
        cls, override_cycles: str, run: SequencingRun
    ) -> str:
        """Adjust override cycles for the sample-sheet i5 orientation.

        Override cycles are always stored in forward orientation. The Index2
        segment must match the orientation of the i5 sequence as it appears
        IN THE SAMPLE SHEET (not the physical-read orientation): per the
        Illumina BCL Convert guidance, when the sample sheet specifies the
        i5 sequence in reverse-complement orientation the N mask is at the
        beginning of the Index2 token (e.g. ``N2I8``); when the sample
        sheet expects forward i5 (NovaSeq X / X Plus, NextSeq 1000/2000,
        MiSeq), the Index2 token stays forward (``I8N2``).

        Previously this keyed off ``get_i5_read_orientation`` (physical),
        which produced ``N2I8`` for NovaSeq X — diverging from the forward
        i5 sequence and corrupting demultiplexing for asymmetric tokens.

        Args:
            override_cycles: Full override cycles string (e.g., "Y151;I8N2;I8N2;Y151")
            run: Sequencing run (provides instrument platform)

        Returns:
            Adjusted override cycles string
        """
        # The Sample model permits a legacy comma separator, but BCL Convert v2
        # uses ';' as the OverrideCycles segment separator — normalize for ALL
        # instruments so a literal comma never reaches the sheet, and so the
        # RC adjustment below can fire on a comma-form value (which would
        # otherwise hit len != 4 and skip the Index2 flip while _resolve_i5
        # still reverse-complements the i5 sequence -> Index2 desync on RC).
        normalized = override_cycles.replace(",", ";")

        orientation = get_samplesheet_v2_i5_orientation(run.instrument_platform)
        if orientation != "reverse-complement":
            return normalized

        parts = normalized.split(";")
        reads = (
            [name for name, _, _ in CycleCalculator.read_structure(run.run_cycles)]
            if run.run_cycles is not None else []
        )
        if "Index2" in reads and len(parts) == len(reads):
            # Locate Index2 from the run's reads — a single-end run has three
            # segments (no Read2) and its Index2 must still be flipped.
            index2_pos = reads.index("Index2")
        elif len(parts) == 4:
            # Four-read layout: no run cycles, or an older stored value (e.g.
            # a trailing 'Y0'). Keep the Index2 flip such values always had.
            index2_pos = 2
        else:
            return normalized

        parts[index2_pos] = CycleCalculator.reverse_override_segment(parts[index2_pos])
        return ";".join(parts)

    @classmethod
    def _resolve_i5(cls, sample, run: Optional[SequencingRun]) -> str:
        """Return the i5 sequence in the orientation that should appear in the
        sample sheet, applying instrument-specific RC where needed.

        Centralised to keep the RC decision in one place. Previously the
        ``_write_application_profile_section`` dispatcher repeated this
        block twice (once for ``Index2``, once for the profile-translated
        ``Index2``), each open to drift.
        """
        i5 = sample.index2_sequence or ""
        if not i5 or run is None:
            return i5
        if get_samplesheet_v2_i5_orientation(run.instrument_platform) == "reverse-complement":
            return _reverse_complement(i5)
        return i5

    @classmethod
    def _escape_csv(cls, value: str) -> str:
        """Escape a value for CSV output.

        Two independent concerns:

        1. Structural: lone CR is quoted as well as LF — a Mac-style line
           ending pasted from an upstream source would otherwise write a
           literal \\r mid-row and split the Sample Sheet into the wrong
           number of columns. Embedded ``,`` and ``"`` are also quoted.

        2. Spreadsheet formula injection: Excel / LibreOffice / Sheets treat
           cells beginning with ``=``, ``+``, ``-``, ``@``, TAB, or CR as
           formulas. A lab operator who opens a Sample Sheet that round-
           tripped a sample_id like ``=cmd|'/c calc.exe'!A1`` would trigger
           code execution. Per the CLAUDE.md input-sanitization rule we
           neutralize these cells by prefixing a single quote (the universal
           "this is text, not a formula" escape) before applying the regular
           CSV quoting. The quote becomes part of the cell text, visible to
           humans but inert to formula parsers.
        """
        if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
            value = "'" + value
        if "," in value or '"' in value or "\n" in value or "\r" in value:
            return '"' + value.replace('"', '""') + '"'
        return value

    @classmethod
    def _escape_identifier(cls, value: str) -> str:
        """Escape a sample identifier (Sample_ID, LibraryName). A name in the
        valid sample ID alphabet (letters, digits, '-', '_') is written
        exactly: it cannot carry a formula payload, and the formula guard's
        "'" prefix on a leading '-' would change the sample's identity in the
        sheet ('-S1' -> "'-S1"). Anything else goes through ``_escape_csv``."""
        if value and _PLAIN_IDENTIFIER_RE.fullmatch(value):
            return value
        return cls._escape_csv(value)

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

        # Accumulate samples per ApplicationProfile across all referencing test_ids,
        # then emit each section once with the unioned sample list. Otherwise samples
        # whose test_id resolves to an already-seen ApplicationProfile would be
        # silently dropped from the section's data rows.
        profile_to_entry: dict[tuple[str, str], dict] = {}
        profile_order: list[tuple[str, str]] = []  # preserve first-seen order for determinism

        for test_id, samples in samples_by_test.items():
            test_profile = test_profile_repo.get_by_test_type(test_id)
            if not test_profile:
                continue

            for app_ref in test_profile.application_profiles:
                profile_key = (app_ref.profile_name, app_ref.profile_version)

                if profile_key not in profile_to_entry:
                    app_profile = app_profile_repo.get_by_name_version(
                        app_ref.profile_name, app_ref.profile_version
                    )
                    if not app_profile:
                        continue
                    profile_to_entry[profile_key] = {"profile": app_profile, "samples": []}
                    profile_order.append(profile_key)

                profile_to_entry[profile_key]["samples"].extend(samples)

        for key in profile_order:
            entry = profile_to_entry[key]
            cls._write_application_profile_section(
                output, entry["profile"], entry["samples"], run
            )

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

        # For the BCLConvert profile specifically, inject the per-run BCL
        # Convert flags (no_lane_splitting, create_fastq_for_index_reads,
        # adapter_behavior). A profile-defined key wins — admin profiles
        # are the source of truth for fixed-per-test-type settings, but
        # per-run toggles must flow through when the profile doesn't
        # explicitly pin them. Without this the operator's "No lane
        # splitting" tick in the wizard would be silently dropped.
        if app_name == "BCLConvert" and run is not None:
            profile_keys = {str(k) for k in profile.settings.keys()}
            for line in cls._format_bclconvert_run_settings(run):
                key = line.split(",", 1)[0]
                if key not in profile_keys:
                    output.write(line)

        for key, value in profile.settings.items():
            output.write(
                f"{cls._escape_csv(str(key))},{cls._escape_csv(str(value))}\n"
            )
        output.write("\n")

        # Write Data section
        output.write(f"[{app_name}_Data]\n")

        # Get data fields from profile, filtering out fields we handle specially
        data_fields = profile.data_fields or list(profile.data.keys())

        # Translate maps a profile field name to its sample sheet column name
        # (e.g. IndexI7 -> Index); BCL Convert does not recognise the
        # untranslated names. The column name drives both the header and the
        # value written, so a translated field is filled like the column it
        # becomes. A YAML "Translate:" key with no entries loads as None.
        translate = profile.translate or {}
        columns = [(field, translate.get(field, field)) for field in data_fields]

        # Write header row — escape admin-defined column names defensively.
        output.write(",".join(cls._escape_csv(str(col)) for _, col in columns) + "\n")

        # BCLConvert: one row per (sample, lane), as in _write_bclconvert_data —
        # writing only the first lane would send the other lanes' reads to
        # Undetermined. Without a Lane column the rows would be identical, so
        # write one. Other applications keep one row per sample (first lane).
        expand_lanes = app_name == "BCLConvert" and any(col == "Lane" for _, col in columns)

        def _row_lanes(sample):
            if expand_lanes and sample.lanes:
                return sample.lanes
            return [sample.lanes[0] if sample.lanes else None]

        rows_to_write = [(sample, lane) for sample in samples for lane in _row_lanes(sample)]

        # Write data rows. Every cell flows through ",".join()
        # so any comma or quote in admin/user-supplied content would shift
        # downstream columns — escape every variable interpolation.
        for sample, lane in rows_to_write:
            row = []
            for field, col in columns:
                if col == "Sample_ID":
                    row.append(cls._escape_identifier(sample.sample_id))
                elif col == "Lane":
                    row.append(str(lane) if lane else "")
                elif col == "Index":
                    # i7 index sequence (model-validated against [ACGTN], but escape defensively)
                    row.append(cls._escape_csv(sample.index1_sequence or ""))
                elif col == "Index2":
                    # i5 sequence in sample-sheet orientation.
                    row.append(cls._escape_csv(cls._resolve_i5(sample, run)))
                elif col == "BarcodeMismatchesIndex1":
                    val = sample.barcode_mismatches_index1
                    row.append(
                        str(val) if val is not None
                        else cls._escape_csv(str(profile.data.get(field, "")))
                    )
                elif col == "BarcodeMismatchesIndex2":
                    val = sample.barcode_mismatches_index2
                    row.append(
                        str(val) if val is not None
                        else cls._escape_csv(str(profile.data.get(field, "")))
                    )
                elif col == "OverrideCycles":
                    # Use sample's override cycles, or calculate from index lengths.
                    # has_index (not index_pair) so combinatorial/single-index
                    # samples also get a computed value, not a blank cell — this
                    # is the production (profile-driven) export path.
                    oc = sample.override_cycles
                    if not oc and sample.has_index and run and run.run_cycles:
                        oc = CycleCalculator.calculate_override_cycles(sample, run.run_cycles)
                    if oc and run:
                        oc = cls._adjust_override_cycles_for_instrument(oc, run)
                    row.append(cls._escape_csv(oc or ""))
                else:
                    # Use default value from profile data
                    row.append(cls._escape_csv(str(profile.data.get(field, ""))))
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
                cls._escape_identifier(sample.sample_id),
                cls._escape_csv(project_name),
                cls._escape_identifier(library_name),
            ]
            output.write(",".join(row) + "\n")

        output.write("\n")
