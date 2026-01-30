"""Test data model for sequencing tests/assays."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid


@dataclass
class Test:
    """A sequencing test or assay that samples can be associated with."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    # Optional configuration
    default_analysis_type: Optional[str] = None  # e.g., "dragen_germline"
    reference_genome: Optional[str] = None  # e.g., "hg38"

    def touch(self) -> None:
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": self.id,
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "default_analysis_type": self.default_analysis_type,
            "reference_genome": self.reference_genome,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Test":
        """Create from dictionary."""
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
            name=data.get("name", ""),
            description=data.get("description", ""),
            created_at=created_at,
            updated_at=updated_at,
            default_analysis_type=data.get("default_analysis_type"),
            reference_genome=data.get("reference_genome"),
        )
