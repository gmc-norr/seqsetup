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

from dataclasses import dataclass, field
from datetime import datetime

from ..utils.clock import utcnow
from .sequencing_run import (InstrumentPlatform, RunStatus, checked_sheet_targets,
                             stored_platform, stored_status)



def _time(value) -> datetime:
    """A stored timestamp: an ISO string is parsed, a datetime is kept, a
    missing one becomes now — as ``SequencingRun.from_dict`` reads it.

    Anything else is **refused**. ``from_dict`` passes such a value through
    and the page then fails on it; a row that quietly showed the current
    time as a run's last change would be a clinical listing stating a time
    nobody made (CLAUDE.md: never silently discard data). Refusing names the
    run on the dashboard instead.
    """
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    if isinstance(value, datetime):
        return value
    if value is None:
        return utcnow()
    raise ValueError(f"a stored timestamp must be text or a date, got {value!r}")


def _bounded(value, limit: int, *, lines: bool = False) -> str:
    """A stored string, clamped the way ``SequencingRun.__setattr__`` clamps
    it, so a row never shows a longer name than the run's own page
    (CLAUDE.md: bound every string at every ingest point)."""
    if not isinstance(value, str):
        return value
    if lines:
        value = value.replace("\r", " ").replace("\n", " ")
    return value[:limit]


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
        # $size refuses anything but an array, and that aborts the WHOLE
        # aggregation: one document whose ``samples`` is a string would take
        # every listing down, where a bad document must only be named. The
        # inner $cond makes sure $size is never handed a non-array; the
        # outer one reports it as null, which ``from_doc`` refuses, so the
        # run reaches the dashboard's "could not be read" line.
        an_array = {"$isArray": {"$ifNull": ["$samples", []]}}
        projected["sample_count"] = {
            "$cond": [an_array,
                      {"$size": {"$cond": [an_array, {"$ifNull": ["$samples", []]}, []]}},
                      None],
        }
        if with_sample_ids:
            projected["samples.sample_id"] = 1
        return projected

    @classmethod
    def from_doc(cls, doc: dict) -> "RunListing":
        """Build a row from a projected document.

        Reads every field exactly as ``SequencingRun.from_dict`` reads it —
        the legacy ``"complete"`` status, the refusal of an unknown status or
        instrument, the timestamps — so a listing never disagrees with the
        page it links to.
        """
        run_id = doc.get("_id") or doc["id"]

        count = doc.get("sample_count")
        if count is None and "sample_count" in doc:
            raise ValueError(f"run {run_id}: samples is stored as something that is not a list")

        status = stored_status(doc, f"Run {run_id!r}")
        platform = stored_platform(doc, f"Run {run_id!r}")

        return cls(
            id=run_id,
            run_name=_bounded(doc.get("run_name", ""), 256, lines=True),
            status=status,
            instrument_platform=platform,
            flowcell_type=_bounded(doc.get("flowcell_type", ""), 256),
            sample_count=int(count or 0),
            created_at=_time(doc.get("created_at")),
            updated_at=_time(doc.get("updated_at")),
            created_by=_bounded(doc.get("created_by", ""), 256),
            updated_by=_bounded(doc.get("updated_by", ""), 256),
            # A Ready or Archived run was ready, whatever the field says —
            # SequencingRun.__setattr__ promotes it the same way.
            was_ready=bool(doc.get("was_ready", False))
            or status in (RunStatus.READY, RunStatus.ARCHIVED),
            # Checked, not merely copied: the API's run list and the API
            # Exports page read every key of it, and a value the run model
            # refuses must not reach them through a listing.
            sheet_targets=checked_sheet_targets(dict(doc.get("sheet_targets") or {})),
        )
