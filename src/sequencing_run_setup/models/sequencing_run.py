"""Sequencing run configuration models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid

from .sample import Sample
from .analysis import Analysis


class RunStatus(Enum):
    """Status of a sequencing run."""

    DRAFT = "draft"
    READY = "ready"
    ARCHIVED = "archived"


class InstrumentPlatform(Enum):
    """Supported instrument platforms."""

    # Four-color SBS
    GAIIX = "GAIIx"
    HISEQ_2000_2500 = "HiSeq 2000/2500"
    HISEQ_4000 = "HiSeq 4000"
    HISEQ_X = "HiSeq X"
    MISEQ = "MiSeq"

    # Two-color SBS (Red+Green)
    NEXTSEQ_500_550 = "NextSeq 500/550"
    MINISEQ = "MiniSeq"
    NOVASEQ_6000 = "NovaSeq 6000"

    # Two-color SBS (Blue+Green, XLEAP)
    NOVASEQ_X = "NovaSeq X Series"
    MISEQ_I100 = "MiSeq i100 Series"
    NEXTSEQ_1000_2000 = "NextSeq 1000/2000"


class NovaSeqXFlowcell(Enum):
    """NovaSeq X flowcell types."""

    FC_1_5B = "1.5B"
    FC_10B = "10B"
    FC_25B = "25B"


class MiSeqI100Flowcell(Enum):
    """MiSeq i100 flowcell types."""

    FC_5M = "5M"
    FC_25M = "25M"
    FC_50M = "50M"
    FC_100M = "100M"


@dataclass
class RunCycles:
    """Read and index cycle configuration."""

    read1_cycles: int
    read2_cycles: int
    index1_cycles: int
    index2_cycles: int

    @property
    def total_cycles(self) -> int:
        """Total number of cycles."""
        return (
            self.read1_cycles
            + self.read2_cycles
            + self.index1_cycles
            + self.index2_cycles
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "read1_cycles": self.read1_cycles,
            "read2_cycles": self.read2_cycles,
            "index1_cycles": self.index1_cycles,
            "index2_cycles": self.index2_cycles,
            "total_cycles": self.total_cycles,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RunCycles":
        """Create from dictionary."""
        return cls(
            read1_cycles=data["read1_cycles"],
            read2_cycles=data["read2_cycles"],
            index1_cycles=data["index1_cycles"],
            index2_cycles=data["index2_cycles"],
        )


@dataclass
class SequencingRun:
    """Configuration for a sequencing run."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    run_name: str = ""
    run_description: str = ""

    # Status and tracking
    status: RunStatus = RunStatus.DRAFT
    validation_approved: bool = False
    created_by: str = ""
    updated_by: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    wizard_step: int = 1

    # Instrument configuration
    instrument_platform: InstrumentPlatform = InstrumentPlatform.NOVASEQ_X
    flowcell_type: str = ""
    reagent_cycles: int = 300

    # Cycle configuration
    run_cycles: Optional[RunCycles] = None

    # BCLConvert settings
    barcode_mismatches_index1: int = 1
    barcode_mismatches_index2: int = 1
    adapter_behavior: str = "trim"
    create_fastq_for_index_reads: bool = False
    no_lane_splitting: bool = False

    # Samples
    samples: list[Sample] = field(default_factory=list)

    # Assigned analyses
    analyses: list[Analysis] = field(default_factory=list)

    def add_sample(self, sample: Sample) -> None:
        """Add a sample to the run."""
        self.samples.append(sample)
        self.validation_approved = False

    def remove_sample(self, sample_id: str) -> None:
        """Remove a sample by ID."""
        self.samples = [s for s in self.samples if s.id != sample_id]
        self.validation_approved = False

    def get_sample(self, sample_id: str) -> Optional[Sample]:
        """Get a sample by ID."""
        for sample in self.samples:
            if sample.id == sample_id:
                return sample
        return None

    def touch(self, reset_validation: bool = True, updated_by: str = "") -> None:
        """Update the updated_at timestamp.

        Args:
            reset_validation: If True, resets validation_approved to False.
                Set to False for status-only changes.
            updated_by: Username of the user making the change.
        """
        self.updated_at = datetime.now()
        if updated_by:
            self.updated_by = updated_by
        if reset_validation:
            self.validation_approved = False

    def add_analysis(self, analysis: Analysis) -> None:
        """Add an analysis."""
        self.analyses.append(analysis)

    def remove_analysis(self, analysis_id: str) -> None:
        """Remove an analysis by ID."""
        self.analyses = [a for a in self.analyses if a.id != analysis_id]

    def get_analysis(self, analysis_id: str) -> Optional[Analysis]:
        """Get an analysis by ID."""
        for analysis in self.analyses:
            if analysis.id == analysis_id:
                return analysis
        return None

    @property
    def has_samples(self) -> bool:
        """Check if run has any samples."""
        return len(self.samples) > 0

    @property
    def all_samples_have_indexes(self) -> bool:
        """Check if all samples have indexes assigned."""
        return all(s.has_index for s in self.samples)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": self.id,
            "id": self.id,
            "run_name": self.run_name,
            "run_description": self.run_description,
            "status": self.status.value,
            "validation_approved": self.validation_approved,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "wizard_step": self.wizard_step,
            "instrument_platform": self.instrument_platform.value,
            "flowcell_type": self.flowcell_type,
            "reagent_cycles": self.reagent_cycles,
            "run_cycles": self.run_cycles.to_dict() if self.run_cycles else None,
            "barcode_mismatches_index1": self.barcode_mismatches_index1,
            "barcode_mismatches_index2": self.barcode_mismatches_index2,
            "adapter_behavior": self.adapter_behavior,
            "create_fastq_for_index_reads": self.create_fastq_for_index_reads,
            "no_lane_splitting": self.no_lane_splitting,
            "samples": [s.to_dict() for s in self.samples],
            "analyses": [a.to_dict() for a in self.analyses],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SequencingRun":
        """Create from dictionary."""
        from datetime import datetime

        run_cycles = None
        if data.get("run_cycles"):
            run_cycles = RunCycles.from_dict(data["run_cycles"])

        # Parse datetime strings
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        elif created_at is None:
            created_at = datetime.now()

        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        elif updated_at is None:
            updated_at = datetime.now()

        return cls(
            id=data.get("_id") or data["id"],
            run_name=data.get("run_name", ""),
            run_description=data.get("run_description", ""),
            status=RunStatus({"complete": "archived"}.get(data.get("status", "draft"), data.get("status", "draft"))),
            validation_approved=data.get("validation_approved", False),
            created_by=data.get("created_by", ""),
            updated_by=data.get("updated_by", ""),
            created_at=created_at,
            updated_at=updated_at,
            wizard_step=data.get("wizard_step", 1),
            instrument_platform=InstrumentPlatform(data.get("instrument_platform", "NovaSeq X Series")),
            flowcell_type=data.get("flowcell_type", ""),
            reagent_cycles=data.get("reagent_cycles", 300),
            run_cycles=run_cycles,
            barcode_mismatches_index1=data.get("barcode_mismatches_index1", 1),
            barcode_mismatches_index2=data.get("barcode_mismatches_index2", 1),
            adapter_behavior=data.get("adapter_behavior", "trim"),
            create_fastq_for_index_reads=data.get("create_fastq_for_index_reads", False),
            no_lane_splitting=data.get("no_lane_splitting", False),
            samples=[Sample.from_dict(s) for s in data.get("samples", [])],
            analyses=[Analysis.from_dict(a) for a in data.get("analyses", [])],
        )
