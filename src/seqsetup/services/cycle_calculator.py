"""Calculate run cycles and override cycles."""

import re
from typing import Optional

from ..data.instruments import get_default_cycles
from ..models.sample import Sample
from ..models.sequencing_run import RunCycles, SequencingRun

# One OverrideCycles segment: one or more tokens, each a letter (Y read,
# I index, U UMI, N mask) followed by a cycle count. With a wildcard, a
# token's count may instead be the internal '*' shorthand.
_SEGMENT_RE = re.compile(r"(?:[YIUN]\d+)+")
_WILDCARD_SEGMENT_RE = re.compile(r"(?:[YIUN](?:\d+|\*))+")


class CycleCalculator:
    """Calculate run cycles and override cycles."""

    @classmethod
    def calculate_run_cycles(
        cls,
        reagent_kit_cycles: int,
        read1_cycles: Optional[int] = None,
        read2_cycles: Optional[int] = None,
        index1_cycles: Optional[int] = None,
        index2_cycles: Optional[int] = None,
    ) -> RunCycles:
        """
        Calculate run cycles based on reagent kit and optional overrides.

        If specific cycles not provided, uses defaults for the reagent kit.

        Args:
            reagent_kit_cycles: Total cycles of the reagent kit (100, 200, 300, etc.)
            read1_cycles: Optional override for Read 1 cycles
            read2_cycles: Optional override for Read 2 cycles
            index1_cycles: Optional override for Index 1 cycles
            index2_cycles: Optional override for Index 2 cycles

        Returns:
            RunCycles configuration
        """
        defaults = get_default_cycles(reagent_kit_cycles)

        return RunCycles(
            read1_cycles=read1_cycles if read1_cycles is not None else defaults["read1"],
            read2_cycles=read2_cycles if read2_cycles is not None else defaults["read2"],
            index1_cycles=index1_cycles if index1_cycles is not None else defaults["index1"],
            index2_cycles=index2_cycles if index2_cycles is not None else defaults["index2"],
        )

    @classmethod
    def calculate_override_cycles(
        cls,
        sample: Sample,
        run_cycles: RunCycles,
    ) -> str:
        """
        Calculate OverrideCycles string for a sample based on index lengths.

        The OverrideCycles string specifies how each read segment should be processed:
        - Y: Use for sequencing (e.g., Y151 = 151 cycles of sequencing)
        - I: Use for index read (e.g., I10 = 10 cycles of index read)
        - U: Use for UMI (e.g., U8 = 8 cycles of UMI)
        - N: Mask/skip cycles (e.g., N2 = skip 2 cycles)

        Format: Y<read1>;I<index1>N<mask1>;I<index2>N<mask2>;Y<read2>

        Examples:
        - Index length matches run cycles: Y151;I10;I10;Y151
        - 8bp index with 10 cycle run: Y151;I8N2;I8N2;Y151
        - No index2: Y151;I10;N10;Y151
        - UMI in read: U8Y*;I10;I10;Y151

        Args:
            sample: Sample with assigned index pair
            run_cycles: Run cycle configuration

        Returns:
            OverrideCycles string
        """
        # Get effective index lengths for override cycles calculation.
        # Priority: sample.index1_cycles/index2_cycles > actual sequence length > 0
        index1_len = cls._get_effective_index_length(sample, 1)
        index2_len = cls._get_effective_index_length(sample, 2)

        # Build override cycles string. One segment per read the run performs
        # (see read_structure): a read with 0 cycles gets no segment.
        parts = []

        # Read 1
        if run_cycles.read1_cycles > 0:
            parts.append(cls._build_read_segment(
                run_cycles.read1_cycles, sample.read1_override_pattern
            ))

        # Index 1
        if run_cycles.index1_cycles > 0:
            parts.append(
                cls._build_index_segment(index1_len, run_cycles.index1_cycles)
            )

        # Index 2
        if run_cycles.index2_cycles > 0:
            parts.append(
                cls._build_index_segment(index2_len, run_cycles.index2_cycles)
            )

        # Read 2 (absent on a single-end run)
        if run_cycles.read2_cycles > 0:
            parts.append(cls._build_read_segment(
                run_cycles.read2_cycles, sample.read2_override_pattern
            ))

        return ";".join(parts)

    @staticmethod
    def read_structure(run_cycles: RunCycles) -> list[tuple[str, str, int]]:
        """(read name, default letter, cycles) for each read the run performs,
        in OverrideCycles order. BCL Convert needs exactly one OverrideCycles
        segment per read in RunInfo.xml, and a read with 0 cycles is not in
        RunInfo — so it gets no segment."""
        reads = [
            ("Read1", "Y", run_cycles.read1_cycles),
            ("Index1", "I", run_cycles.index1_cycles),
            ("Index2", "I", run_cycles.index2_cycles),
            ("Read2", "Y", run_cycles.read2_cycles),
        ]
        return [read for read in reads if read[2] > 0]

    @classmethod
    def expand_override_cycles(
        cls, override_cycles: Optional[str], run_cycles: Optional[RunCycles]
    ) -> Optional[str]:
        """Expand the internal ``*`` wildcard into concrete cycle counts.

        ``*`` is SeqSetup-internal shorthand for "the remaining cycles of this
        read". BCL Convert's OverrideCycles field requires explicit counts, so
        an operator-entered wildcard must be resolved against the run's declared
        cycles — each ``*`` becomes that read's run cycles minus any fixed
        UMI/mask cycles in the same segment — before the value can ship in a
        Sample Sheet.

        Returns the value unchanged when it holds no wildcard. Raises
        ``ValueError`` when a wildcard is present but cannot be resolved: no run
        cycles are configured, or the segment count does not match the run's
        Read/Index structure. We refuse to guess the mapping for clinical output.

        Args:
            override_cycles: Operator-entered OverrideCycles string (may be None)
            run_cycles: Run cycle configuration (may be None)

        Returns:
            OverrideCycles string with every ``*`` expanded to a concrete count
        """
        if not override_cycles:
            return override_cycles
        # Refuse a malformed value outright: the token parser below
        # (re.findall) silently drops what it cannot read, which would turn a
        # typo such as 'Y*Q' or '151' into a different, valid-looking value.
        for seg in re.split(r"[;,]", override_cycles.upper()):
            if not cls.is_valid_override_segment(seg, allow_wildcard=True):
                raise ValueError(
                    f"{override_cycles!r} is not valid OverrideCycles: segment "
                    f"{seg!r} must be letters Y, I, U or N, each followed by a "
                    f"cycle count (e.g. 'Y151;I8N2;I8N2;Y151')."
                )
        if "*" not in override_cycles:
            return override_cycles
        if run_cycles is None:
            raise ValueError(
                "Cannot expand the '*' wildcard in OverrideCycles without "
                "configured run cycles."
            )

        # Mirror the segment order calculate_override_cycles emits: one per
        # read with > 0 cycles.
        reads = cls.read_structure(run_cycles)
        totals = [cycles for _, _, cycles in reads]

        segments = [seg for seg in re.split(r"[;,]", override_cycles) if seg]
        if len(segments) != len(totals):
            structure = "/".join(name for name, _, _ in reads)
            raise ValueError(
                f"OverrideCycles {override_cycles!r} has {len(segments)} "
                f"segment(s), but this run's cycles imply {len(totals)} "
                f"({structure}). Cannot expand the '*' wildcard."
            )

        expanded = []
        for seg, total in zip(segments, totals):
            if "*" not in seg:
                expanded.append(seg.upper())
                continue
            if seg.count("*") > 1:
                # Each '*' claims all remaining cycles, so two in one segment
                # would over-count. Reject visibly rather than store a bad value.
                raise ValueError(
                    f"OverrideCycles segment {seg!r} has more than one '*' "
                    f"wildcard; a segment may use at most one."
                )
            expanded.append(cls._build_read_segment(total, seg))
        return ";".join(expanded)

    @staticmethod
    def is_valid_override_segment(segment: str, allow_wildcard: bool = False) -> bool:
        """True if an uppercased OverrideCycles segment is well-formed, so
        parsing it drops nothing. ``allow_wildcard`` also accepts '*' counts."""
        pattern = _WILDCARD_SEGMENT_RE if allow_wildcard else _SEGMENT_RE
        return pattern.fullmatch(segment) is not None

    @classmethod
    def _build_index_segment(cls, index_len: int, run_cycles: int) -> str:
        """
        Build the override cycles segment for an index read.

        Args:
            index_len: Length of the index sequence
            run_cycles: Number of cycles configured for this index read

        Returns:
            Index segment string (e.g., "I10", "I8N2", "N10")
        """
        if index_len == 0:
            # No index - mask all cycles
            return f"N{run_cycles}"
        elif index_len == run_cycles:
            # Index length matches exactly
            return f"I{index_len}"
        elif index_len < run_cycles:
            # Index shorter than cycles - read index then mask remainder
            mask = run_cycles - index_len
            return f"I{index_len}N{mask}"
        else:
            # Index longer than cycles - only read available cycles
            return f"I{run_cycles}"

    @classmethod
    def _build_read_segment(cls, total_cycles: int, pattern: Optional[str] = None) -> str:
        """
        Build the override cycles segment for a read, applying an optional pattern.

        Patterns use Illumina override cycle notation with * as wildcard:
        - Y (sequencing read), I (index read), U (UMI), N (mask/skip)
        - "Y*" or None: default, read all cycles → "Y151"
        - "N2Y*": skip 2, read rest → "N2Y149"
        - "Y*N2": read, skip last 2 → "Y149N2"
        - "U8Y*": 8 UMI cycles then read rest → "U8Y143"
        - "N2Y*N3": skip 2, read middle, skip 3 → "N2Y146N3"

        The * is replaced with the remaining cycles after accounting for
        all fixed segments in the pattern.

        Args:
            total_cycles: Total number of cycles available for this read
            pattern: Override pattern string, or None for default Y{total}

        Returns:
            Read segment string (e.g., "Y151", "N2Y149")
        """
        if not pattern:
            return f"Y{total_cycles}"

        # Parse the pattern to find fixed segments and the * wildcard
        # Pattern consists of segments like N2, Y*, U8, Y100, N3
        # Supported letters: Y (read), I (index), U (UMI), N (mask/skip)
        import re

        segments = re.findall(r'([YIUN])(\d+|\*)', pattern.upper())
        if not segments:
            return f"Y{total_cycles}"

        # Calculate the sum of fixed cycle counts (non-* segments)
        fixed_cycles = 0
        has_wildcard = False
        for letter, count in segments:
            if count == '*':
                has_wildcard = True
            else:
                fixed_cycles += int(count)

        if not has_wildcard:
            # No wildcard - use pattern as-is (user specified exact cycles)
            return pattern.upper()

        # Replace * with remaining cycles
        remaining = max(0, total_cycles - fixed_cycles)
        result_parts = []
        for letter, count in segments:
            if count == '*':
                result_parts.append(f"{letter}{remaining}")
            else:
                result_parts.append(f"{letter}{count}")

        return "".join(result_parts)

    @classmethod
    def _get_effective_index_length(cls, sample: Sample, index_num: int) -> int:
        """
        Get the effective index length for override cycles calculation.

        Priority:
        1. Sample's explicit index cycles setting (index1_cycles/index2_cycles)
        2. Actual sequence length from assigned index
        3. 0 if no index assigned

        Args:
            sample: Sample to get index length for
            index_num: 1 for index1 (i7), 2 for index2 (i5)

        Returns:
            Effective index length in cycles
        """
        if index_num == 1:
            # Check for explicit override first
            if sample.index1_cycles is not None:
                return sample.index1_cycles
            # Fall back to actual sequence length
            if sample.index_pair:
                return sample.index_pair.index1_length
            if sample.index1:
                return sample.index1.length
            return 0
        else:  # index_num == 2
            # Check for explicit override first
            if sample.index2_cycles is not None:
                return sample.index2_cycles
            # Fall back to actual sequence length
            if sample.index_pair:
                return sample.index_pair.index2_length
            if sample.index2:
                return sample.index2.length
            return 0

    @classmethod
    def infer_global_override_cycles(cls, run: SequencingRun) -> Optional[str]:
        """
        Infer a global OverrideCycles value if all samples have same index lengths.

        This is used for the [BCLConvert_Settings] section when all samples
        can share the same override cycles.

        Args:
            run: Sequencing run configuration

        Returns:
            Global OverrideCycles string, or None if samples have different index lengths
        """
        if not run.samples or not run.run_cycles:
            # No samples or no run cycles configured
            if run.run_cycles:
                return ";".join(
                    f"{letter}{cycles}"
                    for _, letter, cycles in cls.read_structure(run.run_cycles)
                )
            return None

        # Check if all samples have same effective index lengths and read patterns
        index1_lengths = set()
        index2_lengths = set()
        read1_patterns = set()
        read2_patterns = set()

        for sample in run.samples:
            # Use effective index lengths (respects sample overrides)
            index1_lengths.add(cls._get_effective_index_length(sample, 1))
            index2_lengths.add(cls._get_effective_index_length(sample, 2))
            read1_patterns.add(sample.read1_override_pattern or "")
            read2_patterns.add(sample.read2_override_pattern or "")

        if (len(index1_lengths) <= 1 and len(index2_lengths) <= 1
                and len(read1_patterns) <= 1 and len(read2_patterns) <= 1):
            # All same - use first sample's override cycles
            return cls.calculate_override_cycles(run.samples[0], run.run_cycles)

        # Mixed lengths - no global override, per-sample required
        return None

    @classmethod
    def update_all_sample_override_cycles(cls, run: SequencingRun) -> None:
        """
        Update override cycles for all samples in a run.

        Call this after changing run cycles or assigning indexes.

        Args:
            run: Sequencing run to update
        """
        if not run.run_cycles:
            return

        for sample in run.samples:
            if sample.has_index:
                cls.populate_index_override_patterns(sample, run.run_cycles)
                sample.override_cycles = cls.calculate_override_cycles(
                    sample, run.run_cycles
                )
            else:
                sample.override_cycles = None
                sample.index1_override_pattern = None
                sample.index2_override_pattern = None

    @classmethod
    def populate_index_override_patterns(cls, sample: Sample, run_cycles: RunCycles) -> None:
        """Compute and store index override patterns on a sample.

        Uses the effective index length (respecting sample/kit cycle overrides)
        and the run's configured index cycles to build patterns like "I8N2".

        Args:
            sample: Sample with assigned indexes (modified in place)
            run_cycles: Run cycle configuration
        """
        if run_cycles.index1_cycles > 0:
            effective_len = cls._get_effective_index_length(sample, 1)
            sample.index1_override_pattern = cls._build_index_segment(
                effective_len, run_cycles.index1_cycles
            )
        if run_cycles.index2_cycles > 0:
            effective_len = cls._get_effective_index_length(sample, 2)
            sample.index2_override_pattern = cls._build_index_segment(
                effective_len, run_cycles.index2_cycles
            )

    @staticmethod
    def reverse_override_segment(segment: str) -> str:
        """Reverse the token order within an override cycles segment.

        Tokens are letter+count pairs like I8, N2, U4, Y151, or letter+'*'
        wildcards like N*. "I8N2" → "N2I8", "I10" → "I10", "I4N*" → "N*I4".

        Args:
            segment: A single override cycles segment (e.g., "I8N2")

        Returns:
            Segment with token order reversed
        """
        import re
        # Match a count OR a '*' wildcard — a '*' token (e.g. "N*") must not be
        # dropped, or an RC-flipped Index2 mask desyncs from the i5 sequence.
        tokens = re.findall(r'[YIUN](?:\d+|\*)', segment.upper())
        if not tokens:
            return segment
        return "".join(reversed(tokens))
