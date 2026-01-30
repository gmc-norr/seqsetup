"""Profile sync configuration model."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ProfileSyncConfig:
    """Configuration for GitHub profile synchronization.

    This is a singleton configuration stored in the settings collection.
    It defines the GitHub repository URL, paths, and sync settings.
    """

    github_repo_url: str = ""  # e.g., "https://github.com/org/profiles"
    github_branch: str = "main"
    test_profiles_path: str = "profiles/test_profiles/"  # Directory path within repo
    application_profiles_path: str = "profiles/application_profiles/"  # Directory path within repo

    sync_enabled: bool = True
    sync_interval_minutes: int = 60

    last_sync_at: Optional[datetime] = None
    last_sync_status: str = ""  # "success", "error", ""
    last_sync_message: str = ""
    last_sync_count: int = 0  # Number of profiles synced

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "github_repo_url": self.github_repo_url,
            "github_branch": self.github_branch,
            "test_profiles_path": self.test_profiles_path,
            "application_profiles_path": self.application_profiles_path,
            "sync_enabled": self.sync_enabled,
            "sync_interval_minutes": self.sync_interval_minutes,
            "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
            "last_sync_status": self.last_sync_status,
            "last_sync_message": self.last_sync_message,
            "last_sync_count": self.last_sync_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ProfileSyncConfig":
        """Create from dictionary."""
        last_sync_at = data.get("last_sync_at")
        if isinstance(last_sync_at, str):
            last_sync_at = datetime.fromisoformat(last_sync_at)

        return cls(
            github_repo_url=data.get("github_repo_url", ""),
            github_branch=data.get("github_branch", "main"),
            test_profiles_path=data.get("test_profiles_path", "profiles/test_profiles/"),
            application_profiles_path=data.get("application_profiles_path", "profiles/application_profiles/"),
            sync_enabled=data.get("sync_enabled", True),
            sync_interval_minutes=data.get("sync_interval_minutes", 60),
            last_sync_at=last_sync_at,
            last_sync_status=data.get("last_sync_status", ""),
            last_sync_message=data.get("last_sync_message", ""),
            last_sync_count=data.get("last_sync_count", 0),
        )
