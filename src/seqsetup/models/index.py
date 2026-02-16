"""Index-related data models."""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

_VALID_DNA_RE = re.compile(r'^[ACGTN]*$')


class IndexType(Enum):
    """Type of sequencing index."""

    I7 = "i7"  # Index1
    I5 = "i5"  # Index2


class IndexMode(Enum):
    """Index kit mode determining how indexes are assigned to samples."""

    UNIQUE_DUAL = "unique_dual"  # Pre-paired i7+i5 indexes
    COMBINATORIAL = "combinatorial"  # Separate i7 and i5 selection per sample
    SINGLE = "single"  # i7 only


@dataclass
class Index:
    """Single index sequence (i7 or i5)."""

    name: str
    sequence: str
    index_type: IndexType
    well_position: Optional[str] = None  # e.g., "A01" for plate-based kits

    @property
    def length(self) -> int:
        """Length of the index sequence."""
        return len(self.sequence)

    def __post_init__(self):
        # Normalize sequence to uppercase
        self.sequence = self.sequence.upper()
        # Validate DNA characters
        if self.sequence and not _VALID_DNA_RE.match(self.sequence):
            invalid = set(self.sequence) - set("ACGTN")
            raise ValueError(
                f"Index sequence contains invalid characters: {invalid}. "
                f"Only A, C, G, T, N are allowed."
            )

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "name": self.name,
            "sequence": self.sequence,
            "index_type": self.index_type.value,
            "well_position": self.well_position,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Index":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            sequence=data["sequence"],
            index_type=IndexType(data["index_type"]),
            well_position=data.get("well_position"),
        )


@dataclass
class IndexPair:
    """A pair of indexes (dual indexing) that can be assigned to a sample."""

    id: str
    name: str
    index1: Index  # i7
    index2: Optional[Index] = None  # i5 (optional for single indexing)
    well_position: Optional[str] = None  # e.g., "A01" for fixed-layout kits

    @property
    def index1_length(self) -> int:
        """Length of index1 (i7) sequence."""
        return self.index1.length

    @property
    def index2_length(self) -> int:
        """Length of index2 (i5) sequence, or 0 if not present."""
        return self.index2.length if self.index2 else 0

    @property
    def index1_sequence(self) -> str:
        """Index1 (i7) sequence."""
        return self.index1.sequence

    @property
    def index2_sequence(self) -> Optional[str]:
        """Index2 (i5) sequence, or None if not present."""
        return self.index2.sequence if self.index2 else None

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "id": self.id,
            "name": self.name,
            "index1": self.index1.to_dict(),
            "index2": self.index2.to_dict() if self.index2 else None,
            "well_position": self.well_position,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IndexPair":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            index1=Index.from_dict(data["index1"]),
            index2=Index.from_dict(data["index2"]) if data.get("index2") else None,
            well_position=data.get("well_position"),
        )


@dataclass
class IndexKit:
    """Collection of indexes from an index adapter kit."""

    name: str
    version: str = "1.0"
    description: str = ""
    index_mode: IndexMode = IndexMode.UNIQUE_DUAL
    index_pairs: list[IndexPair] = field(default_factory=list)  # For unique_dual mode
    i7_indexes: list[Index] = field(default_factory=list)  # For combinatorial/single mode
    i5_indexes: list[Index] = field(default_factory=list)  # For combinatorial mode
    is_fixed_layout: bool = False
    comments: str = ""  # Free-text notes (e.g. manufacturer ID, batch number)
    adapter_read1: Optional[str] = None  # Adapter sequence for trimming
    adapter_read2: Optional[str] = None

    # Default index lengths to use for override cycles calculation.
    # If set, these override the actual sequence lengths when calculating
    # override cycles. Useful when only part of the index should be used
    # for demultiplexing (e.g., use 8bp of a 10bp index).
    # None = use actual sequence length
    default_index1_cycles: Optional[int] = None  # i7 length for override cycles
    default_index2_cycles: Optional[int] = None  # i5 length for override cycles

    # Default read override patterns using Illumina override cycle notation.
    # Uses Y (read), I (index), U (UMI), N (mask/skip) with * for remaining cycles.
    # Examples: "Y*" (default), "N2Y*" (skip 2 then read), "U8Y*" (8 UMI then read)
    # None = use default Y{cycles} for the full read
    default_read1_override: Optional[str] = None
    default_read2_override: Optional[str] = None

    created_by: str = ""  # Username of who uploaded this kit
    source: str = "user"  # "user" for uploaded kits, "github" for synced kits

    def __post_init__(self):
        # Clamp default index cycles to positive values if set
        if self.default_index1_cycles is not None:
            self.default_index1_cycles = max(1, self.default_index1_cycles)
        if self.default_index2_cycles is not None:
            self.default_index2_cycles = max(1, self.default_index2_cycles)

    @property
    def kit_id(self) -> str:
        """Composite identity: name:version."""
        return f"{self.name}:{self.version}"

    def is_unique_dual(self) -> bool:
        """Check if kit uses unique dual index mode (pre-paired)."""
        return self.index_mode == IndexMode.UNIQUE_DUAL

    def is_combinatorial(self) -> bool:
        """Check if kit uses combinatorial index mode (separate i7/i5 selection)."""
        return self.index_mode == IndexMode.COMBINATORIAL

    def is_single(self) -> bool:
        """Check if kit uses single index mode (i7 only)."""
        return self.index_mode == IndexMode.SINGLE

    def get_index_pair_by_id(self, pair_id: str) -> Optional[IndexPair]:
        """Find an index pair by its ID."""
        for pair in self.index_pairs:
            if pair.id == pair_id:
                return pair
        return None

    def get_index_pair_by_name(self, name: str) -> Optional[IndexPair]:
        """Find an index pair by its name."""
        for pair in self.index_pairs:
            if pair.name == name:
                return pair
        return None

    def get_index_by_id(self, index_id: str) -> Optional[Index]:
        """Find an individual index by its ID (for combinatorial/single mode)."""
        for idx in self.i7_indexes:
            if f"{self.name}_i7_{idx.name}" == index_id:
                return idx
        for idx in self.i5_indexes:
            if f"{self.name}_i5_{idx.name}" == index_id:
                return idx
        return None

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": self.kit_id,  # Use name:version as MongoDB _id
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "index_mode": self.index_mode.value,
            "index_pairs": [pair.to_dict() for pair in self.index_pairs],
            "i7_indexes": [idx.to_dict() for idx in self.i7_indexes],
            "i5_indexes": [idx.to_dict() for idx in self.i5_indexes],
            "is_fixed_layout": self.is_fixed_layout,
            "comments": self.comments,
            "adapter_read1": self.adapter_read1,
            "adapter_read2": self.adapter_read2,
            "default_index1_cycles": self.default_index1_cycles,
            "default_index2_cycles": self.default_index2_cycles,
            "default_read1_override": self.default_read1_override,
            "default_read2_override": self.default_read2_override,
            "created_by": self.created_by,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IndexKit":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            version=data.get("version", "1.0"),
            description=data.get("description", ""),
            index_mode=IndexMode(data.get("index_mode", "unique_dual")),
            index_pairs=[IndexPair.from_dict(p) for p in data.get("index_pairs", [])],
            i7_indexes=[Index.from_dict(i) for i in data.get("i7_indexes", [])],
            i5_indexes=[Index.from_dict(i) for i in data.get("i5_indexes", [])],
            is_fixed_layout=data.get("is_fixed_layout", False),
            comments=data.get("comments", ""),
            adapter_read1=data.get("adapter_read1"),
            adapter_read2=data.get("adapter_read2"),
            default_index1_cycles=data.get("default_index1_cycles"),
            default_index2_cycles=data.get("default_index2_cycles"),
            default_read1_override=data.get("default_read1_override"),
            default_read2_override=data.get("default_read2_override"),
            created_by=data.get("created_by", ""),
            source=data.get("source", "user"),
        )
