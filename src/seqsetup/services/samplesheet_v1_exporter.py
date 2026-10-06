"""Generate Illumina SampleSheet v1 (IEM) format."""

import re
from io import StringIO
from typing import Optional, TextIO

from ..data.instruments import run_i5_direction
from ..models.sequencing_run import InstrumentPlatform, SequencingRun
from .cycle_calculator import CycleCalculator
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
    def withheld(
        cls, run: SequencingRun, mismatches: Optional[dict] = None,
    ) -> tuple[str, list[str]]:
        """Why this run's v1 sheet cannot be made, and the samples it names;
        ("", []) when it can (spec 2026-10-05 group A3, §3). A v1 sheet has
        one pair of mismatch numbers for the whole run, no OverrideCycles,
        and a Lane column only when some sample has lanes. ``mismatches`` is
        the sheet plan's (sample id, index number) -> the number the checks
        used; without it a sample's number is its own, else the run's.

        An index shorter than its read, masked after it (I8N2), is no
        reason: bcl2fastq, which reads v1 sheets, uses the shortened
        sequence (Illumina's bcl2fastq to BCL Convert comparison)."""
        numbers, override, lanes = [], [], []
        any_lanes = any(sample.lanes for sample in run.samples)
        for sample in run.samples:
            name = sample.sample_id or sample.id
            for index_num, sequence, own, run_number in (
                (1, sample.index1_sequence, sample.barcode_mismatches_index1,
                 run.barcode_mismatches_index1),
                (2, sample.index2_sequence, sample.barcode_mismatches_index2,
                 run.barcode_mismatches_index2),
            ):
                checked = (mismatches or {}).get(
                    (sample.id, index_num), own if own is not None else run_number)
                if sequence and checked != run_number and name not in numbers:
                    numbers.append(name)
            oc = sample.override_cycles
            if not oc and sample.has_index and run.run_cycles:
                oc = CycleCalculator.calculate_override_cycles(sample, run.run_cycles)
            if oc and run.run_cycles and cls._parts(oc) != cls._plain_override_cycles(sample, run):
                override.append(name)
            if any_lanes and not sample.lanes:
                lanes.append(name)

        reasons = []
        if numbers:
            reasons.append(
                f"{cls._ids(numbers)} were checked with mismatch numbers other than the run's "
                f"(i7 {run.barcode_mismatches_index1}, i5 {run.barcode_mismatches_index2}), "
                f"which a v1 sheet writes")
        if override:
            reasons.append(f"{cls._ids(override)} have OverrideCycles a v1 sheet cannot hold")
        if lanes:
            reasons.append(f"{cls._ids(lanes)} have no lanes picked while other samples do")
        names = list(dict.fromkeys(numbers + override + lanes))
        return "; ".join(reasons), names

    @staticmethod
    def _ids(names: list[str]) -> str:
        return ", ".join(names[:5]) + (f", and {len(names) - 5} more" if len(names) > 5 else "")

    @staticmethod
    def _parts(override_cycles: str) -> list[str]:
        return re.split(r"[;,]", override_cycles.upper())

    @staticmethod
    def _plain_override_cycles(sample, run: SequencingRun) -> list[str]:
        """The OverrideCycles that follows from the index lengths alone — no
        kit index cycles, no read patterns: what a v1 reader does itself."""
        parts = []
        for name, letter, cycles in CycleCalculator.read_structure(run.run_cycles):
            if letter == "Y":
                parts.append(f"Y{cycles}")
            else:
                sequence = sample.index1_sequence if name == "Index1" else sample.index2_sequence
                parts.append(CycleCalculator._build_index_segment(len(sequence or ""), cycles))
        return parts

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
