"""Run template model — a reusable run configuration with optional scaffold samples.

A RunTemplate is deliberately NOT a SequencingRun and has no status: it lives
entirely outside the run state machine, dashboard, JSON API, and export
pipeline. New runs are produced from it via services.run_builder.build_draft_run.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .analysis import Analysis
from .sample import Sample, checked_mismatches
from .sequencing_run import InstrumentPlatform, RunCycles


@dataclass
class RunTemplate:
    """A saved, reusable run configuration plus optional scaffold samples."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""

    created_by: str = ""
    updated_by: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    run_description: str = ""
    instrument_platform: InstrumentPlatform = InstrumentPlatform.NOVASEQ_X
    flowcell_type: str = ""
    reagent_cycles: int = 300
    run_cycles: Optional[RunCycles] = None
    barcode_mismatches_index1: int = 1
    barcode_mismatches_index2: int = 1
    adapter_behavior: str = "trim"
    create_fastq_for_index_reads: bool = False
    no_lane_splitting: bool = False
    analyses: list[Analysis] = field(default_factory=list)

    scaffold_samples: list[Sample] = field(default_factory=list)

    def __post_init__(self):
        pass

    def __setattr__(self, name, value):
        if name == "name" and isinstance(value, str):
            value = value.replace("\r", " ").replace("\n", " ")[:256]
        elif name in ("description", "run_description") and isinstance(value, str):
            value = value.replace("\r", " ").replace("\n", " ")[:4096]
        elif name == "reagent_cycles":
            value = max(1, value)
        elif name in ("barcode_mismatches_index1", "barcode_mismatches_index2"):
            value = checked_mismatches(name, value)
        elif name in ("created_by", "updated_by", "flowcell_type") and isinstance(value, str):
            value = value[:256]
        object.__setattr__(self, name, value)

    def touch(self, updated_by: str = "") -> None:
        self.updated_at = datetime.now()
        if updated_by:
            self.updated_by = updated_by

    def to_dict(self) -> dict:
        return {
            "_id": self.id,
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "run_description": self.run_description,
            "instrument_platform": self.instrument_platform.value,
            "flowcell_type": self.flowcell_type,
            "reagent_cycles": self.reagent_cycles,
            "run_cycles": self.run_cycles.to_dict() if self.run_cycles else None,
            "barcode_mismatches_index1": self.barcode_mismatches_index1,
            "barcode_mismatches_index2": self.barcode_mismatches_index2,
            "adapter_behavior": self.adapter_behavior,
            "create_fastq_for_index_reads": self.create_fastq_for_index_reads,
            "no_lane_splitting": self.no_lane_splitting,
            "analyses": [a.to_dict() for a in self.analyses],
            "scaffold_samples": [s.to_dict() for s in self.scaffold_samples],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RunTemplate":
        run_cycles = RunCycles.from_dict(data["run_cycles"]) if data.get("run_cycles") else None

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

        raw_platform = data.get("instrument_platform", "NovaSeq X Series")
        try:
            platform = InstrumentPlatform(raw_platform)
        except ValueError:
            import logging
            logging.getLogger(__name__).warning(
                "Unknown InstrumentPlatform %r in stored template %r — falling back to NOVASEQ_X",
                raw_platform, data.get("_id") or data.get("id"),
            )
            platform = InstrumentPlatform.NOVASEQ_X

        return cls(
            id=data.get("_id") or data["id"],
            name=data.get("name", ""),
            description=data.get("description", ""),
            created_by=data.get("created_by", ""),
            updated_by=data.get("updated_by", ""),
            created_at=created_at,
            updated_at=updated_at,
            run_description=data.get("run_description", ""),
            instrument_platform=platform,
            flowcell_type=data.get("flowcell_type", ""),
            reagent_cycles=data.get("reagent_cycles", 300),
            run_cycles=run_cycles,
            barcode_mismatches_index1=data.get("barcode_mismatches_index1", 1),
            barcode_mismatches_index2=data.get("barcode_mismatches_index2", 1),
            adapter_behavior=data.get("adapter_behavior", "trim"),
            create_fastq_for_index_reads=data.get("create_fastq_for_index_reads", False),
            no_lane_splitting=data.get("no_lane_splitting", False),
            analyses=[Analysis.from_dict(a) for a in data.get("analyses", [])],
            scaffold_samples=[Sample.from_dict(s) for s in data.get("scaffold_samples", [])],
        )
