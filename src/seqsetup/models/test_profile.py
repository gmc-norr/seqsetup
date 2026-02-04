"""Test profile model for sequencing test configurations."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid


@dataclass
class ApplicationProfileReference:
    """Reference to an ApplicationProfile within a TestProfile."""

    profile_name: str = ""  # ApplicationProfileName
    profile_version: str = ""  # PEP 440 version constraint (e.g., "~=1.0.0")

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "profile_name": self.profile_name,
            "profile_version": str(self.profile_version),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ApplicationProfileReference":
        """Create from dictionary."""
        return cls(
            profile_name=data.get("profile_name", ""),
            profile_version=str(data.get("profile_version", "")),
        )

    @classmethod
    def from_yaml(cls, yaml_data: dict) -> "ApplicationProfileReference":
        """Create from parsed YAML data.

        Expected YAML structure:
            ApplicationProfileName: BCLConvertNextera
            ApplicationProfileVersion: "~=1.0.0"
        """
        return cls(
            profile_name=yaml_data.get("ApplicationProfileName", ""),
            profile_version=str(yaml_data.get("ApplicationProfileVersion", "")),
        )


@dataclass
class TestProfile:
    """Test profile defining a sequencing test type with associated application profiles.

    Test profiles are synced from a GitHub repository and define which
    application profiles should be used for a specific test type (e.g., WGS, RNA).
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    test_type: str = ""  # TestType (e.g., "WGS") - matches sample.test_id
    test_name: str = ""  # TestName
    description: str = ""  # Description
    version: str = ""  # Version

    # List of application profiles this test uses
    application_profiles: list[ApplicationProfileReference] = field(default_factory=list)

    # Sync metadata
    source_file: str = ""  # Original filename from GitHub
    synced_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "_id": self.id,
            "id": self.id,
            "test_type": self.test_type,
            "test_name": self.test_name,
            "description": self.description,
            "version": str(self.version),
            "application_profiles": [ap.to_dict() for ap in self.application_profiles],
            "source_file": self.source_file,
            "synced_at": self.synced_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TestProfile":
        """Create from dictionary."""
        synced_at = data.get("synced_at")
        if isinstance(synced_at, str):
            synced_at = datetime.fromisoformat(synced_at)
        elif synced_at is None:
            synced_at = datetime.now()

        app_profiles = [
            ApplicationProfileReference.from_dict(ap)
            for ap in data.get("application_profiles", [])
        ]

        return cls(
            id=data.get("_id") or data.get("id") or str(uuid.uuid4()),
            test_type=data.get("test_type", ""),
            test_name=data.get("test_name", ""),
            description=data.get("description", ""),
            version=str(data.get("version", "")),
            application_profiles=app_profiles,
            source_file=data.get("source_file", ""),
            synced_at=synced_at,
        )

    @classmethod
    def from_yaml(cls, yaml_data: dict, source_file: str = "") -> "TestProfile":
        """Create from parsed YAML data.

        Expected YAML structure:
            TestType: WGS
            TestName: WGS
            Description: Whole Genome Sequencing
            Version: 1.0.0
            ApplicationProfiles:
              - ApplicationProfileName: BCLConvertNextera
                ApplicationProfileVersion: "~=1.0.0"
              - ApplicationProfileName: DragenGermlineIdtWgs
                ApplicationProfileVersion: "~=1.0.0"

        Raises:
            ProfileValidationError: If required fields are missing or invalid.
        """
        from ..services.profile_validator import validate_test_profile_yaml

        validate_test_profile_yaml(yaml_data, source_file)

        app_profiles = [
            ApplicationProfileReference.from_yaml(ap)
            for ap in yaml_data.get("ApplicationProfiles", [])
        ]

        return cls(
            id=str(uuid.uuid4()),
            test_type=yaml_data.get("TestType", ""),
            test_name=yaml_data.get("TestName", ""),
            description=yaml_data.get("Description", ""),
            version=str(yaml_data.get("Version", "")),
            application_profiles=app_profiles,
            source_file=source_file,
            synced_at=datetime.now(),
        )
