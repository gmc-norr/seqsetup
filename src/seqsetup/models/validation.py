"""Validation data models for sequencing runs."""

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..data.instruments import ChemistryType


class ColorBalanceStatus(Enum):
    """Status of color balance at a position."""

    OK = "ok"  # Good balance
    WARNING = "warning"  # Suboptimal but usable
    ERROR = "error"  # Poor balance, may cause issues


@dataclass
class PositionColorBalance:
    """Color balance data for a single position in an index.

    Channel assignments are instrument-specific. For 2-color SBS:

    XLEAP (Blue+Green) - NovaSeq X, MiSeq i100:
      Channel 1 (Blue):  A + C
      Channel 2 (Green): C + T
      Dark: G

    Red+Green (older) - NextSeq 500/550, NovaSeq 6000:
      Channel 1 (Red):   A + C
      Channel 2 (Green): A + T
      Dark: G
    """

    position: int  # 1-indexed position
    a_count: int = 0
    c_count: int = 0
    g_count: int = 0
    t_count: int = 0

    # Channel configuration (set from instrument config)
    channel1_name: str = "Channel 1"
    channel1_bases: tuple = ("A", "C")  # Default: XLEAP Blue
    channel2_name: str = "Channel 2"
    channel2_bases: tuple = ("C", "T")  # Default: XLEAP Green

    def _base_count(self, base: str) -> int:
        """Get count for a specific base letter."""
        return {"A": self.a_count, "C": self.c_count, "G": self.g_count, "T": self.t_count}.get(base, 0)

    @property
    def total(self) -> int:
        """Total number of bases at this position."""
        return self.a_count + self.c_count + self.g_count + self.t_count

    @property
    def channel1_count(self) -> int:
        """Bases that produce signal in channel 1."""
        return sum(self._base_count(b) for b in self.channel1_bases)

    @property
    def channel2_count(self) -> int:
        """Bases that produce signal in channel 2."""
        return sum(self._base_count(b) for b in self.channel2_bases)

    @property
    def channel1_percent(self) -> float:
        """Percentage of bases with channel 1 signal."""
        return (self.channel1_count / self.total * 100) if self.total > 0 else 0

    @property
    def channel2_percent(self) -> float:
        """Percentage of bases with channel 2 signal."""
        return (self.channel2_count / self.total * 100) if self.total > 0 else 0

    @property
    def status(self) -> ColorBalanceStatus:
        """Evaluate color balance status.

        Error if:
        - All bases are dark (no signal in either channel)
        - Either channel is 0%

        Warning if:
        - Either channel is below 25%
        """
        if self.total == 0:
            return ColorBalanceStatus.OK

        # No signal in either channel
        if self.channel1_count == 0 and self.channel2_count == 0:
            return ColorBalanceStatus.ERROR

        # One channel has no signal
        if self.channel1_count == 0 or self.channel2_count == 0:
            return ColorBalanceStatus.ERROR

        # Low signal in either channel (< 25%)
        if self.channel1_percent < 25 or self.channel2_percent < 25:
            return ColorBalanceStatus.WARNING

        return ColorBalanceStatus.OK


@dataclass
class IndexColorBalance:
    """Color balance for all positions of an index type (i7 or i5)."""

    index_type: str  # "i7" or "i5"
    positions: list[PositionColorBalance] = field(default_factory=list)

    @property
    def max_position(self) -> int:
        """Maximum position number."""
        return max((p.position for p in self.positions), default=0)

    @property
    def has_issues(self) -> bool:
        """Check if any position has warnings or errors."""
        return any(p.status != ColorBalanceStatus.OK for p in self.positions)

    @property
    def error_count(self) -> int:
        """Count positions with errors."""
        return sum(1 for p in self.positions if p.status == ColorBalanceStatus.ERROR)

    @property
    def warning_count(self) -> int:
        """Count positions with warnings."""
        return sum(1 for p in self.positions if p.status == ColorBalanceStatus.WARNING)


@dataclass
class LaneColorBalance:
    """Color balance analysis for a single lane."""

    lane: int
    sample_count: int
    i7_balance: Optional[IndexColorBalance] = None
    i5_balance: Optional[IndexColorBalance] = None

    @property
    def has_issues(self) -> bool:
        """Check if lane has any color balance issues."""
        i7_issues = self.i7_balance.has_issues if self.i7_balance else False
        i5_issues = self.i5_balance.has_issues if self.i5_balance else False
        return i7_issues or i5_issues


@dataclass
class DarkCycleError:
    """Error when a sample's index starts with two dark bases."""

    sample_id: str  # Internal UUID
    sample_name: str  # Display name (sample_id field)
    index_type: str  # "i7" or "i5"
    sequence: str  # The index sequence
    dark_base: str  # The dark base (e.g., "G")

    @property
    def description(self) -> str:
        """Human-readable description."""
        return (
            f"{self.sample_name}: {self.index_type} index ({self.sequence}) "
            f"starts with two dark bases ({self.dark_base}{self.dark_base})"
        )


@dataclass
class SampleDarkCycleInfo:
    """Dark cycle analysis for a single sample's indexes."""

    sample_id: str  # Internal UUID
    sample_name: str  # Display name
    i7_sequence: str  # i7 index sequence (as stored)
    i5_sequence: str  # i5 index sequence (as stored)
    i5_read_sequence: str  # i5 sequence as read by instrument (may be RC)
    dark_base: str  # The dark base for this chemistry (e.g., "G")
    i7_leading_dark: int  # Number of leading dark bases in i7 (0, 1, or 2)
    i5_leading_dark: int  # Number of leading dark bases in i5 read sequence (0, 1, or 2)


class ValidationSeverity(Enum):
    """Severity level for validation issues."""

    ERROR = "error"
    WARNING = "warning"


@dataclass
class ConfigurationError:
    """A run configuration error or warning.

    Used for: lane assignment issues, index length inconsistency,
    mixed indexing mode, sample ID characters, run cycles vs index length,
    missing lane assignments, duplicate index pairs, barcode mismatch threshold issues.
    """

    severity: ValidationSeverity
    category: str  # e.g. "lane_out_of_range", "index_length_mismatch", etc.
    message: str  # Human-readable description
    sample_names: list[str] = field(default_factory=list)  # Affected samples (if applicable)
    lane: Optional[int] = None  # Affected lane (if applicable)


@dataclass
class ApplicationValidationError:
    """Error when a sample's application profile is not available on the instrument."""

    sample_id: str  # Internal UUID
    sample_name: str  # Display name
    test_id: str  # The sample's test_id
    application_name: str  # e.g. "DragenGermline"
    profile_name: str  # ApplicationProfileName
    error_type: str  # "app_not_available", "version_not_available", "profile_not_found", "test_profile_not_found"
    detail: str  # Human-readable message


@dataclass
class IndexCollision:
    """Represents a collision between two indexes in the same lane."""

    sample1_id: str  # Internal UUID
    sample1_name: str  # Display name (sample_id field)
    sample2_id: str
    sample2_name: str
    lane: int  # Lane where collision occurs
    index_type: str  # "i7" or "i5"
    sequence1: str
    sequence2: str
    hamming_distance: int
    mismatch_threshold: int

    @property
    def collision_description(self) -> str:
        """Human-readable description of the collision."""
        return (
            f"{self.index_type} collision in lane {self.lane}: "
            f"{self.sample1_name} ({self.sequence1}) vs "
            f"{self.sample2_name} ({self.sequence2}) - "
            f"distance {self.hamming_distance} <= threshold {self.mismatch_threshold}"
        )


@dataclass
class IndexDistanceMatrix:
    """Matrix of index distances for heatmap visualization."""

    sample_ids: list[str]  # Internal UUIDs
    sample_names: list[str]  # Display names
    i7_distances: list[list[Optional[int]]]  # 2D matrix (None on diagonal)
    i5_distances: list[list[Optional[int]]]  # 2D matrix (None on diagonal)
    combined_distances: list[list[Optional[int]]]  # Sum of i7 + i5 distances

    def get_i7_distance(self, idx1: int, idx2: int) -> Optional[int]:
        """Get i7 distance between samples at indices."""
        return self.i7_distances[idx1][idx2]

    def get_i5_distance(self, idx1: int, idx2: int) -> Optional[int]:
        """Get i5 distance between samples at indices."""
        return self.i5_distances[idx1][idx2]

    def get_combined_distance(self, idx1: int, idx2: int) -> Optional[int]:
        """Get combined (i7 + i5) distance between samples at indices."""
        return self.combined_distances[idx1][idx2]


@dataclass
class ValidationResult:
    """Complete validation result for a run."""

    duplicate_sample_ids: list[str]  # Error messages
    index_collisions: list[IndexCollision]
    distance_matrices: dict[int, IndexDistanceMatrix]  # Lane -> matrix
    dark_cycle_errors: list[DarkCycleError] = field(default_factory=list)
    dark_cycle_samples: list[SampleDarkCycleInfo] = field(default_factory=list)  # Per-sample dark cycle info
    color_balance: dict[int, LaneColorBalance] = field(default_factory=dict)  # Lane -> balance
    application_errors: list[ApplicationValidationError] = field(default_factory=list)
    configuration_errors: list[ConfigurationError] = field(default_factory=list)
    chemistry_type: Optional[str] = None  # "2-color" or "4-color"
    color_balance_enabled: bool = True  # Whether color balance analysis is shown for this instrument
    channel_config: Optional[dict] = None  # Dye channel configuration from instruments.yaml

    @property
    def has_errors(self) -> bool:
        """Check if there are any validation errors."""
        return (
            len(self.duplicate_sample_ids) > 0
            or len(self.index_collisions) > 0
            or len(self.dark_cycle_errors) > 0
            or len(self.application_errors) > 0
            or any(e.severity == ValidationSeverity.ERROR for e in self.configuration_errors)
        )

    @property
    def error_count(self) -> int:
        """Total number of errors."""
        return (
            len(self.duplicate_sample_ids)
            + len(self.index_collisions)
            + len(self.dark_cycle_errors)
            + len(self.application_errors)
            + sum(1 for e in self.configuration_errors if e.severity == ValidationSeverity.ERROR)
        )

    @property
    def warning_count(self) -> int:
        """Total number of warnings."""
        return sum(1 for e in self.configuration_errors if e.severity == ValidationSeverity.WARNING)

    @property
    def color_balance_issue_count(self) -> int:
        """Count lanes with color balance issues."""
        return sum(1 for lb in self.color_balance.values() if lb.has_issues)

    def get_lane_matrix(self, lane: int) -> Optional[IndexDistanceMatrix]:
        """Get distance matrix for a specific lane."""
        return self.distance_matrices.get(lane)

    def get_lane_color_balance(self, lane: int) -> Optional[LaneColorBalance]:
        """Get color balance for a specific lane."""
        return self.color_balance.get(lane)
