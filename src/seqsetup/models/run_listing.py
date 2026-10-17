"""One row of a listing of runs — a name, a status, a date and a count.

docs/design/2026-10-17-listing-summaries-design.md. The dashboard, its tabs,
its search, /served-runs and GET /api/runs used to load every run document in
full, every sample, to show this much. They now read a projection and build
one of these.

It is deliberately **not** a ``SequencingRun``: ``RunRepository.save`` refuses
anything else, so a listing can never write a run back without its samples or
its export manifest. It is frozen for the same reason — a row is read, never
edited.

It is called ``RunListing`` and not ``RunSummary`` because ``api/schemas.py``
already has a ``RunSummary``: the JSON object the API returns. Two types of
one name in one request path is how a wrong field gets served.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from ..utils.clock import utcnow
from .sequencing_run import InstrumentPlatform, RunStatus


logger = logging.getLogger(__name__)


def _time(value) -> datetime:
    """A stored timestamp, read exactly as ``SequencingRun.from_dict`` reads
    it: an ISO string is parsed, a datetime is kept, anything else (a missing
    field) becomes now."""
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    if isinstance(value, datetime):
        return value
    return utcnow()


@dataclass(frozen=True)
class RunListing:
    """What a listing shows of one run. Read-only; never saved."""

    #: The stored fields a listing reads. ``sample_count`` is computed by the
    #: query, not stored. Nothing here is big or grows with the run.
    FIELDS = ("id", "run_name", "status", "was_ready", "created_by", "updated_by",
              "created_at", "updated_at", "instrument_platform", "flowcell_type",
              "sheet_targets")

    id: str
    run_name: str
    status: RunStatus
    instrument_platform: InstrumentPlatform
    flowcell_type: str
    sample_count: int
    created_at: datetime
    updated_at: datetime
    created_by: str = ""
    updated_by: str = ""
    was_ready: bool = False
    sheet_targets: dict = field(default_factory=dict)

    @classmethod
    def projection(cls, *, with_sample_ids: bool = False) -> dict:
        """The ``$project`` stage. ``sample_count`` is counted in the
        database; ``with_sample_ids`` adds the one field of each sample the
        dashboard's search matches on, and no other."""
        projected: dict = {name: 1 for name in cls.FIELDS}
        projected["sample_count"] = {"$size": {"$ifNull": ["$samples", []]}}
        if with_sample_ids:
            projected["samples.sample_id"] = 1
        return projected

    @classmethod
    def from_doc(cls, doc: dict) -> "RunListing":
        """Build a row from a projected document.

        Reads every field exactly as ``SequencingRun.from_dict`` reads it —
        the legacy ``"complete"`` status, the fallbacks for an unknown status
        or instrument, the timestamps — so a listing never disagrees with the
        page it links to.
        """
        run_id = doc.get("_id") or doc["id"]

        raw_status = "archived" if doc.get("status") == "complete" else doc.get("status", "draft")
        try:
            status = RunStatus(raw_status)
        except ValueError:
            logger.warning(
                "Unknown RunStatus %r in stored run %r — falling back to DRAFT",
                raw_status, run_id,
            )
            status = RunStatus.DRAFT

        raw_platform = doc.get("instrument_platform", "NovaSeq X Series")
        try:
            platform = InstrumentPlatform(raw_platform)
        except ValueError:
            logger.warning(
                "Unknown InstrumentPlatform %r in stored run %r — falling back to NOVASEQ_X",
                raw_platform, run_id,
            )
            platform = InstrumentPlatform.NOVASEQ_X

        return cls(
            id=run_id,
            run_name=doc.get("run_name", ""),
            status=status,
            instrument_platform=platform,
            flowcell_type=doc.get("flowcell_type", ""),
            sample_count=int(doc.get("sample_count") or 0),
            created_at=_time(doc.get("created_at")),
            updated_at=_time(doc.get("updated_at")),
            created_by=doc.get("created_by", ""),
            updated_by=doc.get("updated_by", ""),
            was_ready=doc.get("was_ready", False),
            sheet_targets=dict(doc.get("sheet_targets") or {}),
        )
