"""Application profile model for DRAGEN application settings."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import uuid

from ..utils.clock import utcnow


def _or_empty(value, empty):
    """An empty YAML section (``Settings:`` with nothing under it) is None; it
    means "none" (spec 2026-09-29 Sample Sheet follow-ups, §1). Mark Ready
    used to fail on ``None.items()``."""
    return empty if value is None else value


@dataclass
class ApplicationProfile:
    """DRAGEN application profile defining settings for samplesheet export.

    Application profiles are synced from a GitHub repository and define
    the settings and data fields for DRAGEN applications like BCLConvert,
    DragenGermline, DragenSomatic, etc.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""  # ApplicationProfileName
    version: str = ""  # ApplicationProfileVersion
    application_type: str = ""  # ApplicationType (e.g., "Dragen")
    application_name: str = ""  # ApplicationName (e.g., "DragenGermline", "BCLConvert")

    # Settings dict (SoftwareVersion, AppVersion, MapAlignOutFormat, etc.)
    settings: dict[str, Any] = field(default_factory=dict)

    # Data dict (ReferenceGenomeDir, VariantCallingMode, etc.)
    data: dict[str, Any] = field(default_factory=dict)

    # List of field names that appear in Data section
    data_fields: list[str] = field(default_factory=list)

    # Translation mapping (e.g., IndexI7 -> Index)
    translate: dict[str, str] = field(default_factory=dict)

    # Sync metadata
    source_file: str = ""  # Original filename from GitHub
    synced_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": self.id,
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "application_type": self.application_type,
            "application_name": self.application_name,
            "settings": self.settings,
            "data": self.data,
            "data_fields": self.data_fields,
            "translate": self.translate,
            "source_file": self.source_file,
            "synced_at": self.synced_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ApplicationProfile":
        """Create from dictionary."""
        synced_at = data.get("synced_at")
        if isinstance(synced_at, str):
            synced_at = datetime.fromisoformat(synced_at)
        elif synced_at is None:
            synced_at = utcnow()

        return cls(
            id=data.get("_id") or data.get("id") or str(uuid.uuid4()),
            name=data.get("name", ""),
            version=str(data.get("version", "")),
            application_type=data.get("application_type", ""),
            application_name=data.get("application_name", ""),
            settings=_or_empty(data.get("settings"), {}),
            data=_or_empty(data.get("data"), {}),
            data_fields=_or_empty(data.get("data_fields"), []),
            translate=_or_empty(data.get("translate"), {}),
            source_file=data.get("source_file", ""),
            synced_at=synced_at,
        )

    @classmethod
    def from_yaml(cls, yaml_data: dict, source_file: str = "") -> "ApplicationProfile":
        """Create from parsed YAML data.

        Expected YAML structure:
            ApplicationProfileName: DragenGermlineIdtWgs
            ApplicationProfileVersion: 1.0.0
            ApplicationType: Dragen
            ApplicationName: DragenGermline
            Settings:
              SoftwareVersion: 4.1.23
              ...
            Data:
              ReferenceGenomeDir: hg38-...
              ...
            DataFields:
              - ReferenceGenomeDir
              - Sample_ID
            Translate:
              IndexI7: Index

        Raises:
            ProfileValidationError: If required fields are missing or invalid.
        """
        from ..services.profile_validator import validate_application_profile_yaml

        validate_application_profile_yaml(yaml_data, source_file)

        return cls(
            id=str(uuid.uuid4()),
            name=yaml_data.get("ApplicationProfileName", ""),
            version=str(yaml_data.get("ApplicationProfileVersion", "")),
            application_type=yaml_data.get("ApplicationType", ""),
            application_name=yaml_data.get("ApplicationName", ""),
            settings=_or_empty(yaml_data.get("Settings"), {}),
            data=_or_empty(yaml_data.get("Data"), {}),
            data_fields=_or_empty(yaml_data.get("DataFields"), []),
            translate=_or_empty(yaml_data.get("Translate"), {}),
            source_file=source_file,
            synced_at=utcnow(),
        )
