"""Sample API configuration model."""

import os
from dataclasses import dataclass, field
from typing import Optional


# Env var that overrides the stored api_key at use time. Setting this in
# production keeps the actual secret out of the MongoDB document.
_API_KEY_ENV = "SEQSETUP_LIMS_API_KEY"


@dataclass
class SampleApiConfig:
    """Configuration for external sample API integration.

    Singleton configuration stored in the settings collection.
    Defines the API base URL, authentication key, enabled state, and field mappings.

    The base URL is used to derive two endpoints:
    - GET {base_url}/worksheets?detail=true — list available worksheets
    - GET {base_url}/worksheets/{id} — get samples for a worksheet

    Field mappings allow translating API field names to SeqSetup field names.
    For example, if the API uses "AL" for worksheet ID, set:
        field_mappings = {"worksheet_id": "AL", "investigator": "Investigator"}
    """

    base_url: str = ""  # e.g. "https://lims.example.com/api"
    api_key: str = ""  # Legacy MongoDB storage; production should use SEQSETUP_LIMS_API_KEY
    enabled: bool = False

    def effective_api_key(self) -> str:
        """Return the api key to use at request time.

        Prefers the SEQSETUP_LIMS_API_KEY environment variable; falls back to
        the stored field for backward compatibility with existing deployments.
        New deployments should set the env var and leave the stored field empty
        so the secret never lives in the database backup.
        """
        env_value = os.environ.get(_API_KEY_ENV, "")
        return env_value or self.api_key

    # Field mappings: SeqSetup field name -> API field name
    # Supported SeqSetup fields: worksheet_id, investigator, updated_at, samples
    field_mappings: dict[str, str] = field(default_factory=dict)

    def worklists_url(
        self,
        status: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> str:
        """URL for listing worksheets with optional filters.

        Args:
            status: Filter by status (e.g., 'KS', 'P', 'A')
            limit: Maximum number of worksheets to return
        """
        base = self.base_url.rstrip("/")
        if not base:
            return ""

        params = ["detail=true"]
        if status:
            params.append(f"status={status}")
        if limit:
            params.append(f"page_size={limit}")

        return f"{base}/worksheets?{'&'.join(params)}"

    def worklist_samples_url(self, worklist_id: str) -> str:
        """URL for fetching samples of a specific worksheet."""
        base = self.base_url.rstrip("/")
        return f"{base}/worksheets/{worklist_id}" if base else ""

    def get_api_field(self, seqsetup_field: str) -> str:
        """Get the API field name for a SeqSetup field.

        Args:
            seqsetup_field: The SeqSetup field name (e.g., "worksheet_id")

        Returns:
            The mapped API field name, or the original name if no mapping exists.
        """
        return self.field_mappings.get(seqsetup_field, seqsetup_field)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage."""
        return {
            "base_url": self.base_url,
            "api_key": self.api_key,
            "enabled": self.enabled,
            "field_mappings": self.field_mappings,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SampleApiConfig":
        """Create from dictionary."""
        return cls(
            base_url=data.get("base_url", ""),
            api_key=data.get("api_key", ""),
            enabled=data.get("enabled", False),
            field_mappings=data.get("field_mappings", {}),
        )
