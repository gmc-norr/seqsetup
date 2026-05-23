"""Pydantic models for the /api/* surface.

These are *response* shapes — Pydantic confined to the API boundary so
the domain layer stays on dataclasses. FastAPI uses these to generate the
OpenAPI schema automatically; that replaces the 500-line hand-maintained
``seqsetup.openapi`` module.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class RunSummary(BaseModel):
    """Minimal run record returned by the list endpoint.

    Sensitive/bulky payloads (samples, pre-generated Sample Sheets, validation
    PDF bytes) are NOT included here — those are behind the explicit per-run
    endpoints. A token-holder enumerating runs should not bulk-dump finalized
    clinical content in a single call.
    """

    id: str = Field(..., description="Run identifier (UUID).")
    run_name: str = Field("", description="Operator-supplied run name.")
    status: str = Field(..., description='"ready" or "archived" — drafts are never returned here.')
    instrument_platform: str = Field(
        ...,
        description="Display name of the Illumina platform (e.g., 'NovaSeq X Series').",
    )
    flowcell_type: str = Field("", description="Flowcell identifier (e.g., '10B').")
    created_at: Optional[datetime] = Field(None, description="UTC creation timestamp.")
    updated_at: Optional[datetime] = Field(None, description="UTC last-modified timestamp.")
    created_by: str = Field("", description="Username of the run creator.")
    sample_count: int = Field(0, ge=0, description="Number of samples in the run.")


class RunListResponse(BaseModel):
    """Paginated list of run summaries."""

    items: list[RunSummary]
    total: int = Field(..., ge=0, description="Total runs matching the status filter (across all pages).")
    limit: int = Field(..., ge=1, description="Page size used for this response.")
    offset: int = Field(..., ge=0, description="Offset into the result set used for this response.")


class ErrorResponse(BaseModel):
    """Standard error envelope for non-2xx responses."""

    detail: str
