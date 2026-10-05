"""Generate Illumina SampleSheet v1 (IEM) format."""

import re
from io import StringIO
from typing import TextIO

from ..data.instruments import run_i5_direction
from ..models.sequencing_run import InstrumentPlatform, SequencingRun
from .sheet_text import refuse_hidden_characters
from ..utils.clock import local_date


# Reverse complement lookup table
_RC = str.maketrans("ACGTacgt", "TGCAtgca")

# The valid sample ID alphabet (ValidationService._SAMPLE_ID_PATTERN). A name
# made only of these characters cannot carry a spreadsheet formula payload.
_PLAIN_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_\-]+")


def _reverse_complement(seq: str) -> str:
    """Return the reverse complement of a DNA sequence."""
    return seq.translate(_RC)[::-1]


class SampleSheetV1Exporter:
    """Generate Illumina SampleSheet v1 (IEM) format for MiSeq and NovaSeq 6000."""

    SUPPORTED_PLATFORMS = {InstrumentPlatform.MISEQ, InstrumentPlatform.NOVASEQ_6000}

    @classmethod
    def supports(cls, platform: InstrumentPlatform) -> bool:
        """Check if instrument supports v1 export."""
        return platform in cls.SUPPORTED_PLATFORMS

    @classmethod
    def export(cls, run: SequencingRun) -> str:
        """Export sequencing run to SampleSheet v1 CSV format.

        Args:
            run: Sequencing run configuration

        Returns:
            SampleSheet v1 content as string
        """
        output = StringIO()

        cls._write_header(output, run)
        cls._write_reads(output, run)
        cls._write_settings(output, run)
        cls._write_data(output, run)

        return output.getvalue()

    @classmethod
    def _write_header(cls, output: TextIO, run: SequencingRun):
        """Write [Header] section."""
        output.write("[Header]\n")
        output.write("IEMFileVersion,4\n")

        if run.created_by:
            output.write(f"Investigator Name,{cls._escape_csv(run.created_by)}\n")

        if run.run_name:
            output.write(f"Experiment Name,{cls._escape_identifier(run.run_name)}\n")

        output.write(f"Date,{local_date(run.created_at)}\n")
        output.write("Workflow,GenerateFASTQ\n")
        output.write("Application,FASTQ Only\n")

        if run.run_description:
            output.write(f"Description,{cls._escape_csv(run.run_description)}\n")

        output.write("Chemistry,Default\n")

        # Include run UUID for linking with extended metadata
        output.write(f"Custom_UUID,{run.id}\n")

        output.write("\n")

    @classmethod
    def _write_reads(cls, output: TextIO, run: SequencingRun):
        """Write [Reads] section with bare cycle counts."""
        output.write("[Reads]\n")

        if run.run_cycles:
            output.write(f"{run.run_cycles.read1_cycles}\n")
            if run.run_cycles.read2_cycles > 0:
                output.write(f"{run.run_cycles.read2_cycles}\n")

        output.write("\n")

    @classmethod
    def _write_settings(cls, output: TextIO, run: SequencingRun):
        """Write [Settings] section."""
        output.write("[Settings]\n")
        output.write("ReverseComplement,0\n")
        output.write(f"BarcodeMismatchesIndex1,{run.barcode_mismatches_index1}\n")
        output.write(f"BarcodeMismatchesIndex2,{run.barcode_mismatches_index2}\n")
        output.write("\n")

    @classmethod
    def _write_data(cls, output: TextIO, run: SequencingRun):
        """Write [Data] section."""
        output.write("[Data]\n")

        # Determine if we need Lane column (multi-lane flowcells like NovaSeq 6000)
        has_lanes = any(len(s.lanes) > 0 for s in run.samples)

        # bcl2fastq compares the i5 as the run's workflow reads it
        # (spec 2026-10-04 group A2, §2).
        rc_i5 = run_i5_direction(run).reads_reversed

        # Header row
        columns = []
        if has_lanes:
            columns.append("Lane")
        columns.extend([
            "Sample_ID", "Sample_Name", "Sample_Project",
            "index", "index2", "Description",
        ])
        output.write(",".join(columns) + "\n")

        # Data rows
        for sample in run.samples:
            i7_seq = sample.index1_sequence or ""
            i5_seq = sample.index2_sequence or ""

            # Reverse-complement i5 for instruments that read RC
            if rc_i5 and i5_seq:
                i5_seq = _reverse_complement(i5_seq)

            lanes_to_output = sample.lanes if sample.lanes else [None]

            for lane in lanes_to_output:
                row = []

                if has_lanes:
                    row.append(str(lane) if lane else "")

                row.append(cls._escape_identifier(sample.sample_id))
                row.append(cls._escape_identifier(sample.sample_name))
                row.append(cls._escape_identifier(sample.project or ""))
                row.append(i7_seq)
                row.append(i5_seq)
                row.append(cls._escape_csv(sample.description or ""))

                output.write(",".join(row) + "\n")

        output.write("\n")

    @classmethod
    def _escape_identifier(cls, value: str) -> str:
        """Escape a sample identifier. A name in the valid sample ID alphabet
        is written exactly — the formula guard's "'" prefix on a leading '-'
        would change the sample's identity. Anything else: ``_escape_csv``."""
        if value and _PLAIN_IDENTIFIER_RE.fullmatch(value):
            return value
        return cls._escape_csv(value)

    @classmethod
    def _escape_csv(cls, value: str) -> str:
        """Escape a value for CSV output. See ``_escape_csv`` in the v2
        exporter for the full rationale — same shape here (structural CR/LF
        + ``,`` + ``"`` quoting, plus a leading-quote prefix on cells that
        would otherwise be interpreted as spreadsheet formulas).
        """
        refuse_hidden_characters(value, allow="\t\n\r")
        if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
            value = "'" + value
        if "," in value or '"' in value or "\n" in value or "\r" in value:
            return '"' + value.replace('"', '""') + '"'
        return value
