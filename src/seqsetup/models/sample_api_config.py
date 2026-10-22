"""Sample API configuration model."""

import os
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

from ..utils.names import is_dot_only


# The only source of the LIMS api-key. It used to be an override over a key
# the admin page stored in the settings document; the secret then sat in every
# database backup and in the form's round trip, so the stored key is no longer
# written, read or used.
API_KEY_ENV = "SEQSETUP_LIMS_API_KEY"

# How many worksheets to ask the LIMS for at once. iGene pages /worksheets and
# answers its own default page -- 20 -- when no page_size is asked for
# (tools/igene_openapi.json, tools/mock_igene_api.py: page_size=Query(20)), so
# a laboratory with more than 20 saw 20 of them with no word about the rest
# (review INGEST-2). One larger page is asked for instead, and
# fetch_worklists says so when the answer's pagination names more than it
# holds; a second page is never fetched, because a list that moves between
# two requests could send one worksheet twice and the duplicate-ID rule would
# then hide it. The parameter's name and this size come from the mock's model
# of iGene and must be confirmed against the real one.
WORKSHEET_PAGE_SIZE = 200


# Worklist IDs are operator-supplied (pasted from a LIMS UI, etc.) and
# end up appended to the LIMS URL. The alphabet is letters, digits, '_',
# '-', '.' and '~'. None of those ends the path segment, but '.' and '..'
# ARE path segments: "{base}/worksheets/.." is a request for "{base}/" to
# any server or proxy that normalises dot segments, sent with the LIMS
# api-key, and whatever JSON came back was previewed or imported as samples.
# So a value made only of dots is refused too (security review 2026-10).
_VALID_WORKLIST_ID_RE = re.compile(r"^[A-Za-z0-9._~\-]+$")


class InvalidWorklistIdError(ValueError):
    """Raised when a worklist_id contains characters unsafe for URL inclusion."""


def validate_worklist_id(worklist_id: str) -> None:
    """Raise InvalidWorklistIdError unless worklist_id is path-segment safe."""
    if not worklist_id:
        raise InvalidWorklistIdError("worklist_id is required")
    if len(worklist_id) > 128:
        raise InvalidWorklistIdError("worklist_id is too long (max 128 chars)")
    # fullmatch: the pattern's $ also matches before a final newline, and
    # "W2\n" passed (review of the fixes after the build of later list slice 2).
    if not _VALID_WORKLIST_ID_RE.fullmatch(worklist_id):
        raise InvalidWorklistIdError(
            f"worklist_id {worklist_id!r} contains unsafe characters. "
            f"Allowed: letters, digits, '.', '_', '-', '~'."
        )
    if is_dot_only(worklist_id):
        raise InvalidWorklistIdError(
            f"worklist_id {worklist_id!r} cannot be made only of dots: a dot segment "
            f"asks the LIMS for a path of its own, not for a worksheet."
        )


@dataclass
class SampleApiConfig:
    """Configuration for external sample API integration.

    Singleton configuration stored in the settings collection.
    Defines the API base URL, enabled state, and field mappings. The api-key
    is not part of it: it comes from the server's own environment
    (``SEQSETUP_LIMS_API_KEY``) and is never stored here.

    The base URL is used to derive two endpoints:
    - GET {base_url}/worksheets?detail=true — list available worksheets
    - GET {base_url}/worksheets/{id} — get samples for a worksheet

    Field mappings allow translating API field names to SeqSetup field names.
    For example, if the API uses "AL" for worksheet ID, set:
        field_mappings = {"worksheet_id": "AL", "investigator": "Investigator"}
    """

    base_url: str = ""  # e.g. "https://lims.example.com/api"
    enabled: bool = False
    # True when the document this was read from still holds a key an older
    # SeqSetup stored. The key itself is not kept: only the admin page's
    # notice needs to know it is there, and saving the page removes it.
    legacy_api_key_stored: bool = False

    def effective_api_key(self) -> str:
        """The api-key to send, from ``SEQSETUP_LIMS_API_KEY`` and nowhere else.

        Empty when the variable is unset: a key in the settings document is
        not read, so no deployment keeps sending a secret nobody can see.
        """
        return os.environ.get(API_KEY_ENV, "")

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
        params.append(f"page_size={limit or WORKSHEET_PAGE_SIZE}")

        return f"{base}/worksheets?{'&'.join(params)}"

    def worklist_samples_url(self, worklist_id: str) -> str:
        """URL for fetching samples of a specific worksheet.

        Validates worklist_id and URL-quotes it before inclusion to prevent
        operator-supplied input from injecting path segments or query
        parameters into the LIMS request. ``quote`` leaves a dot alone, so it
        is ``validate_worklist_id`` -- not the quoting -- that keeps an ID of
        dots from climbing out of /worksheets/.
        """
        validate_worklist_id(worklist_id)
        base = self.base_url.rstrip("/")
        if not base:
            return ""
        # quote with safe="" so '/' and other delimiters inside the worklist_id
        # are percent-encoded (defence-in-depth — the regex already blocks them).
        return f"{base}/worksheets/{quote(worklist_id, safe='')}"

    def get_api_field(self, seqsetup_field: str) -> str:
        """Get the API field name for a SeqSetup field.

        Args:
            seqsetup_field: The SeqSetup field name (e.g., "worksheet_id")

        Returns:
            The mapped API field name, or the original name if no mapping exists.
        """
        return self.field_mappings.get(seqsetup_field, seqsetup_field)

    def to_dict(self) -> dict:
        """Convert to dictionary for MongoDB storage.

        No ``api_key``: the repository replaces the whole document, so saving
        the settings page removes a key an older version left there.
        ``legacy_api_key_stored`` is read from the document, never written to
        it.
        """
        return {
            "base_url": self.base_url,
            "enabled": self.enabled,
            "field_mappings": self.field_mappings,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SampleApiConfig":
        """Create from dictionary. A stored api-key is noted, not kept."""
        return cls(
            base_url=data.get("base_url", ""),
            enabled=data.get("enabled", False),
            field_mappings=data.get("field_mappings", {}),
            legacy_api_key_stored=bool(data.get("api_key")),
        )
