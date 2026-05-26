"""Sequencing run configuration models."""

import base64
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

    def __post_init__(self):
        # Invariant enforcement lives in __setattr__ so both construction
        # and direct attribute writes from routes go through the same
        # clamping.
        pass

    def __setattr__(self, name, value):
        # Clamp every cycle count to a sane range on every assignment.
        # Lower bound 0 (some workflows legitimately set read2=0 for
        # single-end). Upper bound 1000 — generously above current Illumina
        # chemistry max (~500) while still catching obviously-bogus values.
        if name in ("read1_cycles", "read2_cycles", "index1_cycles", "index2_cycles"):
            value = max(0, min(1000, value))
        object.__setattr__(self, name, value)

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

    # Pre-generated exports (populated when status transitions to READY).
    #
    # Encryption-at-rest note (audit M3)
    # ----------------------------------
    # These fields may contain sample identifiers and other clinical
    # metadata once a run is approved. They are stored plaintext in the
    # MongoDB document. For deployments that need protection against
    # backup or storage-level disclosure, encrypt at the *storage* layer:
    #   - MongoDB's built-in encryption-at-rest (Enterprise) or
    #     client-side field-level encryption (CSFLE), or
    #   - Encrypted block storage on the host running mongod.
    # Application-level wrapping of these fields would multiply the
    # key-management surface for negligible additional benefit and is
    # intentionally not done here.
    generated_samplesheet_v2: Optional[str] = None
    generated_samplesheet_v1: Optional[str] = None
    generated_json: Optional[str] = None
    generated_validation_json: Optional[str] = None
    generated_validation_pdf: Optional[bytes] = None  # PDF bytes, base64-encoded in MongoDB

    # Optimistic-locking token captured at load time. Set by from_dict to the
    # parsed updated_at; touch() does NOT change this. The RunRepository.save
    # path uses this value in the document filter and raises ConflictError if
    # a concurrent edit has bumped the stored updated_at. None means "freshly
    # constructed, never loaded" — save inserts without a version check.
    _loaded_updated_at: Optional[datetime] = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self):
        # Invariants live in __setattr__ so direct attribute writes from
        # route handlers can't bypass them.
        pass

    def __setattr__(self, name, value):
        # Clamp on every assignment, not just construction. Routes do
        # ``run.barcode_mismatches_index1 = …`` directly; without this the
        # clamps in __post_init__ wouldn't re-fire.
        if name == "reagent_cycles":
            value = max(1, value)
        elif name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
            value = max(0, min(3, value))
        object.__setattr__(self, name, value)

    def add_sample(self, sample: Sample) -> None:
        """Add a sample to the run."""
        self.samples.append(sample)

    def remove_sample(self, sample_id: str) -> None:
        """Remove a sample by ID."""
        self.samples = [s for s in self.samples if s.id != sample_id]

    def get_sample(self, sample_id: str) -> Optional[Sample]:
        """Get a sample by ID."""
        for sample in self.samples:
            if sample.id == sample_id:
                return sample
        return None

    def _require_sample(self, sample_id: str) -> Sample:
        sample = self.get_sample(sample_id)
        if sample is None:
            raise ValueError(f"Sample {sample_id!r} not found in run")
        return sample

    def assign_index_pair_to_sample(self, sample_id: str, index_pair) -> None:
        self._require_sample(sample_id).assign_index(index_pair)

    def assign_index1_to_sample(self, sample_id: str, index) -> None:
        self._require_sample(sample_id).assign_index1(index)

    def assign_index2_to_sample(self, sample_id: str, index) -> None:
        self._require_sample(sample_id).assign_index2(index)

    def clear_sample_index(self, sample_id: str) -> None:
        self._require_sample(sample_id).clear_index()

    def clear_sample_index1(self, sample_id: str) -> None:
        self._require_sample(sample_id).clear_index1()

    def clear_sample_index2(self, sample_id: str) -> None:
        self._require_sample(sample_id).clear_index2()

    def touch(self, updated_by: str = "") -> None:
        """Update the updated_at timestamp.

        Args:
            updated_by: Username of the user making the change.
        """
        self.updated_at = datetime.now()
        if updated_by:
            self.updated_by = updated_by

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
            "generated_samplesheet_v2": self.generated_samplesheet_v2,
            "generated_samplesheet_v1": self.generated_samplesheet_v1,
            "generated_json": self.generated_json,
            "generated_validation_json": self.generated_validation_json,
            "generated_validation_pdf": (
                base64.b64encode(self.generated_validation_pdf).decode("ascii")
                if self.generated_validation_pdf else None
            ),
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

        # Defensive enum parsing: an unknown status or instrument_platform
        # (e.g. from a renamed enum value in a future release, or a
        # corrupted document) must not make an archived clinical run
        # unloadable. Surface a warning and fall back to a safe value.
        raw_status = "archived" if data.get("status") == "complete" else data.get("status", "draft")
        try:
            status = RunStatus(raw_status)
        except ValueError:
            import logging
            logging.getLogger(__name__).warning(
                "Unknown RunStatus %r in stored run %r — falling back to DRAFT",
                raw_status, data.get("_id") or data.get("id"),
            )
            # Falling back to DRAFT (not ARCHIVED) keeps the run out of the
            # JSON API surface (which exposes only Ready + Archived) and out
            # of the export pipeline until an admin re-examines it. A
            # corrupted status field should never silently become a clinical
            # snapshot.
            status = RunStatus.DRAFT

        raw_platform = data.get("instrument_platform", "NovaSeq X Series")
        try:
            platform = InstrumentPlatform(raw_platform)
        except ValueError:
            import logging
            logging.getLogger(__name__).warning(
                "Unknown InstrumentPlatform %r in stored run %r — falling back to NOVASEQ_X",
                raw_platform, data.get("_id") or data.get("id"),
            )
            platform = InstrumentPlatform.NOVASEQ_X

        return cls(
            id=data.get("_id") or data["id"],
            run_name=data.get("run_name", ""),
            run_description=data.get("run_description", ""),
            status=status,
            created_by=data.get("created_by", ""),
            updated_by=data.get("updated_by", ""),
            created_at=created_at,
            updated_at=updated_at,
            wizard_step=data.get("wizard_step", 1),
            instrument_platform=platform,
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
            generated_samplesheet_v2=data.get("generated_samplesheet_v2") or data.get("generated_samplesheet"),
            generated_samplesheet_v1=data.get("generated_samplesheet_v1"),
            generated_json=data.get("generated_json"),
            generated_validation_json=data.get("generated_validation_json"),
            generated_validation_pdf=(
                base64.b64decode(data["generated_validation_pdf"])
                if data.get("generated_validation_pdf") else None
            ),
            # Snapshot the load-time updated_at so optimistic-locked saves
            # can detect concurrent edits (see RunRepository.save).
            _loaded_updated_at=updated_at,
        )
