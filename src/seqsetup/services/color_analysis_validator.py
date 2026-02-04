"""Color balance and dark cycle analysis for sequencing runs.

This module handles instrument-specific 2-color chemistry validation:
- Dark cycle detection (indexes starting with consecutive dark bases)
- Color balance calculation per position across samples
"""

from collections import defaultdict
from typing import Optional

from ..data.instruments import get_lanes_for_flowcell
from ..models.sample import Sample
from ..models.sequencing_run import SequencingRun
from ..models.validation import (
    DarkCycleError,
    IndexColorBalance,
    LaneColorBalance,
    PositionColorBalance,
    SampleDarkCycleInfo,
)
from .validation_utils import reverse_complement


class ColorAnalysisValidator:
    """Validator for color balance and dark cycle analysis."""

    @classmethod
    def validate_dark_cycles(
        cls,
        run: SequencingRun,
        channel_config: Optional[dict] = None,
        i5_orientation: str = "forward",
    ) -> list[DarkCycleError]:
        """
        Check for indexes that start with two consecutive dark bases.

        On 2-color SBS instruments, a dark base produces no signal in either
        channel. If the first two bases of an index are both dark, the
        instrument cannot reliably detect the index read start. One dark base
        in the first two positions is acceptable; both dark is an error.

        Args:
            run: Sequencing run
            channel_config: Dye channel configuration (must contain "dark_base")
            i5_orientation: "forward" or "reverse-complement"

        Returns:
            List of DarkCycleError for each affected sample/index
        """
        if not channel_config:
            return []

        dark_base = channel_config.get("dark_base", "").upper()
        if not dark_base:
            return []

        errors = []
        for sample in run.samples:
            display_name = sample.sample_id or sample.sample_name or sample.id

            # Check i7 (index1)
            i7_seq = sample.index1_sequence
            if i7_seq and len(i7_seq) >= 2:
                if i7_seq[0].upper() == dark_base and i7_seq[1].upper() == dark_base:
                    errors.append(
                        DarkCycleError(
                            sample_id=sample.id,
                            sample_name=display_name,
                            index_type="i7",
                            sequence=i7_seq,
                            dark_base=dark_base,
                        )
                    )

            # Check i5 (index2) - use the read orientation the instrument sees
            i5_seq = sample.index2_sequence
            if i5_seq and len(i5_seq) >= 2:
                read_seq = (
                    reverse_complement(i5_seq)
                    if i5_orientation == "reverse-complement"
                    else i5_seq
                )
                if (
                    read_seq[0].upper() == dark_base
                    and read_seq[1].upper() == dark_base
                ):
                    errors.append(
                        DarkCycleError(
                            sample_id=sample.id,
                            sample_name=display_name,
                            index_type="i5",
                            sequence=i5_seq,
                            dark_base=dark_base,
                        )
                    )

        return errors

    @classmethod
    def build_dark_cycle_info(
        cls,
        run: SequencingRun,
        channel_config: Optional[dict] = None,
        i5_orientation: str = "forward",
    ) -> list[SampleDarkCycleInfo]:
        """
        Build per-sample dark cycle information for visualization.

        Returns info for every sample that has at least one index sequence,
        including the number of leading dark bases for each index.
        """
        if not channel_config:
            return []

        dark_base = channel_config.get("dark_base", "").upper()
        if not dark_base:
            return []

        results = []
        for sample in run.samples:
            i7_seq = sample.index1_sequence or ""
            i5_seq = sample.index2_sequence or ""

            if not i7_seq and not i5_seq:
                continue

            display_name = sample.sample_id or sample.sample_name or sample.id

            # Compute i5 read sequence
            if i5_seq and i5_orientation == "reverse-complement":
                i5_read = reverse_complement(i5_seq)
            else:
                i5_read = i5_seq

            # Count leading dark bases
            i7_leading = 0
            for base in i7_seq[:2]:
                if base.upper() == dark_base:
                    i7_leading += 1
                else:
                    break

            i5_leading = 0
            for base in i5_read[:2]:
                if base.upper() == dark_base:
                    i5_leading += 1
                else:
                    break

            results.append(
                SampleDarkCycleInfo(
                    sample_id=sample.id,
                    sample_name=display_name,
                    i7_sequence=i7_seq,
                    i5_sequence=i5_seq,
                    i5_read_sequence=i5_read,
                    dark_base=dark_base,
                    i7_leading_dark=i7_leading,
                    i5_leading_dark=i5_leading,
                )
            )

        return results

    @classmethod
    def calculate_color_balance(
        cls,
        run: SequencingRun,
        channel_config: Optional[dict] = None,
        i5_orientation: str = "forward",
        instrument_config=None,
    ) -> dict[int, LaneColorBalance]:
        """
        Calculate color balance for index positions per lane.

        Channel assignments are determined by the instrument's channel_config.
        i5 sequences are reverse-complemented when the instrument reads them
        in that orientation, so color balance reflects the actual bases seen
        by the sequencer at each cycle.

        Args:
            run: Sequencing run
            channel_config: Dye channel configuration from instruments.yaml
            i5_orientation: "forward" or "reverse-complement"
            instrument_config: Optional InstrumentConfig for DB overrides

        Returns:
            Dict mapping lane number to LaneColorBalance
        """
        # Determine total lanes from flowcell
        total_lanes = get_lanes_for_flowcell(
            run.instrument_platform, run.flowcell_type, instrument_config
        )
        all_lanes = list(range(1, total_lanes + 1))

        # Group samples by lane
        lane_samples: dict[int, list[Sample]] = defaultdict(list)

        for sample in run.samples:
            if not sample.has_index:
                continue  # Skip samples without indexes

            if sample.lanes:
                for lane in sample.lanes:
                    lane_samples[lane].append(sample)
            else:
                # Empty lanes = all lanes
                for lane in all_lanes:
                    lane_samples[lane].append(sample)

        # Calculate color balance for each lane
        result: dict[int, LaneColorBalance] = {}

        for lane in sorted(lane_samples.keys()):
            samples = lane_samples[lane]
            if samples:
                result[lane] = cls._calculate_lane_color_balance(
                    lane, samples, channel_config, i5_orientation
                )

        return result

    @classmethod
    def _calculate_lane_color_balance(
        cls,
        lane: int,
        samples: list[Sample],
        channel_config: Optional[dict] = None,
        i5_orientation: str = "forward",
    ) -> LaneColorBalance:
        """
        Calculate color balance for a single lane.

        Args:
            lane: Lane number
            samples: Samples in this lane
            channel_config: Dye channel configuration
            i5_orientation: "forward" or "reverse-complement"

        Returns:
            LaneColorBalance with i7 and i5 balance data
        """
        # Collect all i7 and i5 sequences
        i7_sequences = [s.index1_sequence for s in samples if s.index1_sequence]
        i5_sequences = [s.index2_sequence for s in samples if s.index2_sequence]

        # Reverse-complement i5 sequences when the instrument reads them that way,
        # so color balance reflects the actual bases at each sequencing cycle
        if i5_orientation == "reverse-complement" and i5_sequences:
            i5_sequences = [reverse_complement(seq) for seq in i5_sequences]

        i7_balance = (
            cls._calculate_index_color_balance("i7", i7_sequences, channel_config)
            if i7_sequences
            else None
        )
        i5_balance = (
            cls._calculate_index_color_balance("i5", i5_sequences, channel_config)
            if i5_sequences
            else None
        )

        return LaneColorBalance(
            lane=lane,
            sample_count=len(samples),
            i7_balance=i7_balance,
            i5_balance=i5_balance,
        )

    @classmethod
    def _calculate_index_color_balance(
        cls,
        index_type: str,
        sequences: list[str],
        channel_config: Optional[dict] = None,
    ) -> IndexColorBalance:
        """
        Calculate color balance for an index type across all sequences.

        Args:
            index_type: "i7" or "i5"
            sequences: List of index sequences
            channel_config: Dye channel configuration

        Returns:
            IndexColorBalance with per-position base counts
        """
        if not sequences:
            return IndexColorBalance(index_type=index_type, positions=[])

        # Extract channel parameters from config
        if channel_config:
            ch1_name = channel_config["channel1_name"]
            ch1_bases = tuple(channel_config["channel1_bases"])
            ch2_name = channel_config["channel2_name"]
            ch2_bases = tuple(channel_config["channel2_bases"])
        else:
            # Fallback defaults (XLEAP Blue+Green)
            ch1_name = "Blue"
            ch1_bases = ("A", "C")
            ch2_name = "Green"
            ch2_bases = ("C", "T")

        # Find max length
        max_len = max(len(seq) for seq in sequences)

        positions = []
        for pos in range(max_len):
            pos_balance = PositionColorBalance(
                position=pos + 1,
                channel1_name=ch1_name,
                channel1_bases=ch1_bases,
                channel2_name=ch2_name,
                channel2_bases=ch2_bases,
            )

            for seq in sequences:
                if pos < len(seq):
                    base = seq[pos].upper()
                    if base == "A":
                        pos_balance.a_count += 1
                    elif base == "C":
                        pos_balance.c_count += 1
                    elif base == "G":
                        pos_balance.g_count += 1
                    elif base == "T":
                        pos_balance.t_count += 1

            positions.append(pos_balance)

        return IndexColorBalance(index_type=index_type, positions=positions)
