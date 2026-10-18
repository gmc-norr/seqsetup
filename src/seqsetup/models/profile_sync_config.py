"""Profile sync configuration model."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ProfileSyncConfig:
    """Configuration for GitHub profile and instrument synchronization.

    This is a singleton configuration stored in the settings collection.
    It defines the GitHub repository URL, paths, and sync settings for
    profiles and instruments.
    """

    github_repo_url: str = ""  # e.g., "https://github.com/org/profiles"
    github_branch: str = "main"
    test_profiles_path: str = "profiles/test_profiles/"  # Directory path within repo
    application_profiles_path: str = "profiles/application_profiles/"  # Directory path within repo
    instruments_path: str = "instruments/"  # Directory path for instrument definitions
    index_kits_path: str = "index_kits/"  # Directory path for index kit definitions

    # Enable/disable sync for each type
    sync_enabled: bool = True
    sync_instruments_enabled: bool = True  # Sync instruments along with profiles
    sync_index_kits_enabled: bool = True  # Sync index kits along with profiles
    sync_interval_minutes: int = 60

    # Profile sync status
    last_sync_at: Optional[datetime] = None
    last_sync_status: str = ""  # "success", "error", ""
    last_sync_message: str = ""
    last_sync_count: int = 0  # Number of profiles synced

    # The repository and branch the last sync actually read, so the status
    # above is never shown under a repository it did not come from. Empty
    # means a status stored before SeqSetup remembered this.
    last_sync_repo_url: str = ""
    last_sync_branch: str = ""

    # The problems the input rules found in the files the last sync read, as
    # plain records (file, line, column, path, message, level), cut to the
    # status budget; how many there were, and how many are not stored
    # (docs/design/2026-10-18-input-rules-design.md).
    last_sync_problems: list = field(default_factory=list)
    last_sync_problem_count: int = 0
    last_sync_problems_left_out: int = 0

    # Instrument sync status (tracked separately)
    last_instruments_sync_count: int = 0

    # Index kit sync status (tracked separately)
    last_index_kits_sync_count: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "github_repo_url": self.github_repo_url,
            "github_branch": self.github_branch,
            "test_profiles_path": self.test_profiles_path,
            "application_profiles_path": self.application_profiles_path,
            "instruments_path": self.instruments_path,
            "index_kits_path": self.index_kits_path,
            "sync_enabled": self.sync_enabled,
            "sync_instruments_enabled": self.sync_instruments_enabled,
            "sync_index_kits_enabled": self.sync_index_kits_enabled,
            "sync_interval_minutes": self.sync_interval_minutes,
            "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
            "last_sync_status": self.last_sync_status,
            "last_sync_message": self.last_sync_message,
            "last_sync_count": self.last_sync_count,
            "last_sync_repo_url": self.last_sync_repo_url,
            "last_sync_branch": self.last_sync_branch,
            "last_sync_problems": list(self.last_sync_problems),
            "last_sync_problem_count": self.last_sync_problem_count,
            "last_sync_problems_left_out": self.last_sync_problems_left_out,
            "last_instruments_sync_count": self.last_instruments_sync_count,
            "last_index_kits_sync_count": self.last_index_kits_sync_count,
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
            instruments_path=data.get("instruments_path", "instruments/"),
            index_kits_path=data.get("index_kits_path", "index_kits/"),
            sync_enabled=data.get("sync_enabled", True),
            sync_instruments_enabled=data.get("sync_instruments_enabled", True),
            sync_index_kits_enabled=data.get("sync_index_kits_enabled", True),
            sync_interval_minutes=data.get("sync_interval_minutes", 60),
            last_sync_at=last_sync_at,
            last_sync_status=data.get("last_sync_status", ""),
            last_sync_message=data.get("last_sync_message", ""),
            last_sync_count=data.get("last_sync_count", 0),
            last_sync_repo_url=data.get("last_sync_repo_url", ""),
            last_sync_branch=data.get("last_sync_branch", ""),
            last_sync_problems=list(data.get("last_sync_problems") or []),
            last_sync_problem_count=data.get("last_sync_problem_count", 0),
            last_sync_problems_left_out=data.get("last_sync_problems_left_out", 0),
            last_instruments_sync_count=data.get("last_instruments_sync_count", 0),
            last_index_kits_sync_count=data.get("last_index_kits_sync_count", 0),
        )
