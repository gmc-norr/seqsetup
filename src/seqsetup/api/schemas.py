"""Pydantic models for the /api/* surface.

These are *response* shapes — Pydantic confined to the API boundary so
the domain layer stays on dataclasses. FastAPI uses these to generate the
OpenAPI schema automatically; that replaces the 500-line hand-maintained
``seqsetup.openapi`` module.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SheetTarget(BaseModel):
    """The instrument and software one stored Sample Sheet was written for."""

    instrument: str = Field(..., description="The run's instrument (e.g., 'NovaSeq X Series').")
    software: str = Field(..., description='"BCL Convert" (v2 sheet) or "bcl2fastq" (v1 sheet).')
    software_version: Optional[str] = Field(
        None, description="The BCL Convert version the v2 sheet states; null when the sheet states none.",
    )
    i5_workflow: str = Field(..., description="The run's i5 workflow.")
    index2_column: str = Field(
        ...,
        description='How the sheet writes each i5: "forward" (as the index kit lists it) '
                    'or "reverse-complement".',
    )
    needs_runinfo_reverse_mark: bool = Field(
        ...,
        description='True when the sheet relies on BCL Convert acting on the IsReverseComplement="Y" '
                    "mark RunInfo.xml puts on the i5 read.",
    )


class SheetTargets(BaseModel):
    """Each stored Sample Sheet's target instrument and software."""

    samplesheet_v2: SheetTarget
    samplesheet_v1: Optional[SheetTarget] = Field(None, description="null when the run has no v1 sheet.")


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
    target: Optional[SheetTargets] = Field(
        None,
        description="Each stored Sample Sheet's target instrument and software, saved by Mark Ready "
                    "with the sheets; null for a run marked Ready before SeqSetup saved it.",
    )


class RunListResponse(BaseModel):
    """Paginated list of run summaries."""

    items: list[RunSummary]
    total: int = Field(..., ge=0, description="Total runs matching the status filter (across all pages).")
    limit: int = Field(..., ge=1, description="Page size used for this response.")
    offset: int = Field(..., ge=0, description="Offset into the result set used for this response.")


class ErrorResponse(BaseModel):
    """Standard error envelope for non-2xx responses."""

    detail: str
