"""Sample API configuration model."""

from dataclasses import dataclass


@dataclass
class SampleApiConfig:
    """Configuration for external sample API integration.

    Singleton configuration stored in the settings collection.
    Defines the API base URL, authentication key, and enabled state.

    The base URL is used to derive two endpoints:
    - GET {base_url}/worklists — list available worklists
    - GET {base_url}/worklists/{id}/samples — get samples for a worklist
    """

    base_url: str = ""  # e.g. "https://lims.example.com/api"
    api_key: str = ""
    enabled: bool = False

    @property
    def worklists_url(self) -> str:
        """URL for listing worklists."""
        base = self.base_url.rstrip("/")
        return f"{base}/worklists" if base else ""

    def worklist_samples_url(self, worklist_id: str) -> str:
        """URL for fetching samples of a specific worklist."""
        base = self.base_url.rstrip("/")
        return f"{base}/worklists/{worklist_id}/samples" if base else ""

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "base_url": self.base_url,
            "api_key": self.api_key,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SampleApiConfig":
        """Create from dictionary."""
        return cls(
            base_url=data.get("base_url", ""),
            api_key=data.get("api_key", ""),
            enabled=data.get("enabled", False),
        )
