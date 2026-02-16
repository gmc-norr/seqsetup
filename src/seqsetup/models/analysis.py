"""Analysis configuration models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import uuid


class AnalysisType(Enum):
    """Type of analysis."""

    DRAGEN_ONBOARD = "dragen_onboard"  # Runs on instrument
    DOWNSTREAM = "downstream"  # Runs after BCL Convert


class DRAGENPipeline(Enum):
    """DRAGEN onboard pipeline types."""

    GERMLINE = "dragen_germline"
    SOMATIC = "dragen_somatic"
    RNA = "dragen_rna"
    ENRICHMENT = "dragen_enrichment"


@dataclass
class Analysis:
    """Analysis configuration for samples."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    analysis_type: AnalysisType = AnalysisType.DOWNSTREAM

    # DRAGEN-specific settings
    dragen_pipeline: Optional[DRAGENPipeline] = None
    reference_genome: str = ""  # e.g., "hg38"

    # Downstream pipeline settings (e.g., nf-core)
    pipeline_name: str = ""  # e.g., "nf-core/sarek"
    pipeline_version: str = ""
    pipeline_params: dict[str, Any] = field(default_factory=dict)

    # Assigned sample IDs
    sample_ids: list[str] = field(default_factory=list)

    def add_sample(self, sample_id: str) -> None:
        """Add a sample to this analysis."""
        if sample_id not in self.sample_ids:
            self.sample_ids.append(sample_id)

    def remove_sample(self, sample_id: str) -> None:
        """Remove a sample from this analysis."""
        if sample_id in self.sample_ids:
            self.sample_ids.remove(sample_id)

    @property
    def is_dragen(self) -> bool:
        """Check if this is a DRAGEN onboard analysis."""
        return self.analysis_type == AnalysisType.DRAGEN_ONBOARD

    @property
    def is_downstream(self) -> bool:
        """Check if this is a downstream analysis."""
        return self.analysis_type == AnalysisType.DOWNSTREAM

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "id": self.id,
            "name": self.name,
            "analysis_type": self.analysis_type.value,
            "dragen_pipeline": self.dragen_pipeline.value if self.dragen_pipeline else None,
            "reference_genome": self.reference_genome,
            "pipeline_name": self.pipeline_name,
            "pipeline_version": self.pipeline_version,
            "pipeline_params": self.pipeline_params,
            "sample_ids": self.sample_ids,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Analysis":
        """Create from dictionary."""
        dragen_pipeline = None
        if data.get("dragen_pipeline"):
            dragen_pipeline = DRAGENPipeline(data["dragen_pipeline"])

        return cls(
            id=data["id"],
            name=data.get("name", ""),
            analysis_type=AnalysisType(data.get("analysis_type", "downstream")),
            dragen_pipeline=dragen_pipeline,
            reference_genome=data.get("reference_genome", ""),
            pipeline_name=data.get("pipeline_name", ""),
            pipeline_version=data.get("pipeline_version", ""),
            pipeline_params=data.get("pipeline_params", {}),
            sample_ids=data.get("sample_ids", []),
        )
