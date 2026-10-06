"""Sequencing run configuration models."""

import base64
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid

from .sample import Sample, checked_mismatches
from .analysis import Analysis
from ..utils.clock import utcnow


def _resolve_max_samples_per_run() -> int:
    """Hard upper bound on samples added to a single run.

    Per-lane index-collision/distance validation is O(n^2); without a cap an
    authenticated user could paste an unbounded number of samples and turn a
    plain validation GET into a memory/CPU denial-of-service on the shared
    clinical app. The default is generous for real clinical multiplexing;
    operators with exceptionally high-plex needs can raise it via
    SEQSETUP_MAX_SAMPLES_PER_RUN, accepting the higher validation cost.
    """
    raw = os.environ.get("SEQSETUP_MAX_SAMPLES_PER_RUN", "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 5000
    return value if value > 0 else 5000


MAX_SAMPLES_PER_RUN = _resolve_max_samples_per_run()


def checked_i5_workflow(value) -> str:
    """A run's or template's i5 workflow name: text, cut to 256 characters,
    line breaks made spaces, as ``run_name`` (spec 2026-10-04 group A2, §3)."""
    if not isinstance(value, str):
        raise ValueError(f"i5_workflow must be text, got {value!r}")
    return value.replace("\r", " ").replace("\n", " ")[:256]


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
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)
    wizard_step: int = 1

    # Instrument configuration
    instrument_platform: InstrumentPlatform = InstrumentPlatform.NOVASEQ_X
    flowcell_type: str = ""
    reagent_cycles: int = 300
    # The run's i5 workflow, one of its instrument's i5_workflows names; ""
    # means the standard one (spec 2026-10-04 group A2, §3).
    i5_workflow: str = ""

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
    # Why Mark Ready made no v1 sheet, when one could not carry the settings
    # the checks used; "" otherwise (spec 2026-10-05 group A3, §3). Stored
    # and cleared with the generated exports.
    samplesheet_v1_withheld: str = ""

    # True once the run has been Ready (or Archived). Kept by __setattr__ and
    # never cleared: it decides who may delete an emptied draft and whether a
    # copy is kept (spec 2026-09-28 group 2a, F16).
    was_ready: bool = False

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
            value = checked_mismatches(name, value)
        elif name == "run_name" and isinstance(value, str):
            # CR/LF in run_name would land verbatim in the Sample Sheet
            # [Header] section and split the line into two — strip them
            # before clamping. 256 char cap matches the route-level
            # sanitize_string limit.
            value = value.replace("\r", " ").replace("\n", " ")[:256]
        elif name == "run_description" and isinstance(value, str):
            value = value.replace("\r", " ").replace("\n", " ")[:4096]
        elif name == "i5_workflow":
            value = checked_i5_workflow(value)
        elif name in ("created_by", "updated_by", "flowcell_type", "reagent_cycles_kit") and isinstance(value, str):
            value = value[:256]
        elif name == "status" and value in (RunStatus.READY, RunStatus.ARCHIVED):
            object.__setattr__(self, "was_ready", True)
        elif name == "was_ready":
            # Never cleared. During __init__ ``status`` is assigned before
            # ``was_ready``, so read both with getattr.
            value = (
                bool(value)
                or getattr(self, "was_ready", False)
                or getattr(self, "status", None) in (RunStatus.READY, RunStatus.ARCHIVED)
            )
        object.__setattr__(self, name, value)

    def add_sample(self, sample: Sample) -> None:
        """Add a sample to the run.

        Refuses once the run is at ``MAX_SAMPLES_PER_RUN`` — the load-bearing
        backstop against unbounded sample counts (which would make the
        O(n^2) index validation a DoS vector). Read the module global at call
        time so the cap can be tuned/tested without re-import.
        """
        if len(self.samples) >= MAX_SAMPLES_PER_RUN:
            raise ValueError(
                f"Run already has the maximum of {MAX_SAMPLES_PER_RUN} samples; "
                f"refusing to add more. Split the work across runs or raise "
                f"SEQSETUP_MAX_SAMPLES_PER_RUN."
            )
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
        self.updated_at = utcnow()
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
            "was_ready": self.was_ready,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "wizard_step": self.wizard_step,
            "instrument_platform": self.instrument_platform.value,
            "flowcell_type": self.flowcell_type,
            "reagent_cycles": self.reagent_cycles,
            "i5_workflow": self.i5_workflow,
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
            "samplesheet_v1_withheld": self.samplesheet_v1_withheld,
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
            created_at = utcnow()

        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        elif updated_at is None:
            updated_at = utcnow()

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
            was_ready=data.get("was_ready", False),
            created_by=data.get("created_by", ""),
            updated_by=data.get("updated_by", ""),
            created_at=created_at,
            updated_at=updated_at,
            wizard_step=data.get("wizard_step", 1),
            instrument_platform=platform,
            flowcell_type=data.get("flowcell_type", ""),
            reagent_cycles=data.get("reagent_cycles", 300),
            i5_workflow=data.get("i5_workflow") or "",
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
            samplesheet_v1_withheld=data.get("samplesheet_v1_withheld") or "",
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
