"""Recording helpers for per-run change history.

Invoked from saving_run (edits) and the creation sites. All callers wrap these
in their own try/except so a history failure never breaks a persisted clinical
edit (the deployment's standalone MongoDB has no transactions; the run save and
the history append are separate writes — best-effort by necessity).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

import bson

from ..models.run_history import RunHistoryEntry
from .audit_log import audit
from .run_diff import diff_run, is_empty

if TYPE_CHECKING:
    from ..context import AppContext
    from ..models.sequencing_run import SequencingRun

_log = logging.getLogger(__name__)

# Safety margin under MongoDB's 16 MB (16,777,216-byte) BSON document cap. A
# bulk paste / worklist import of up to MAX_SAMPLES_PER_RUN samples is recorded
# as ONE entry with a before/after snapshot per sample field; that can exceed
# the cap and the oversized insert would be swallowed by the best-effort guard,
# silently dropping the most audit-worthy edit. We summarize before it gets
# there so the trail always records that the bulk change happened.
_MAX_ENTRY_BSON_BYTES = 15_000_000


def _summarize_sample_changes(sample_changes: list) -> list:
    """Collapse a large per-sample change list into a single count-only entry.
    Per-field detail is dropped (it is what made the entry oversized); the
    counts preserve that N samples were added/removed/modified."""
    counts = {"added": 0, "removed": 0, "modified": 0}
    for sc in sample_changes:
        kind = sc.get("kind")
        if kind in counts:
            counts[kind] += 1
    return [{
        "sample_id": None,
        "kind": "summary",
        "fields": [],
        "summary": {**counts, "total": len(sample_changes)},
    }]


def _summarize_field_changes(field_changes: list) -> list:
    """Collapse run-level field changes into a single count-only marker. Only
    used in the pathological case where even the sample-summarized entry is
    still over the cap (an unbounded run-level field diff)."""
    return [{
        "field": "(summary)",
        "before": None,
        "after": (f"{len(field_changes)} run-field changes; "
                  "detail omitted (entry too large to record in full)"),
    }]


def _entry_too_large(entry: RunHistoryEntry) -> bool:
    """True if the entry's BSON encoding would approach the document cap. On any
    encoding error, treat as too large so we fall back to the compact summary
    rather than risk an oversized insert that the guard would silently drop."""
    try:
        return len(bson.encode(entry.to_dict())) > _MAX_ENTRY_BSON_BYTES
    except Exception:
        return True


def record_run_updated(
    ctx: AppContext, run: SequencingRun, before: dict, actor: str
) -> None:
    """Diff `before` (pre-mutation to_dict) against the run's current state and
    append an 'updated' entry if anything tracked changed. No-op if nothing
    changed or history isn't configured."""
    if ctx.run_history_repo is None:
        return
    field_changes, sample_changes = diff_run(before, run.to_dict())
    if is_empty(field_changes, sample_changes):
        return
    entry = RunHistoryEntry(
        run_id=run.id,
        timestamp=run.updated_at,
        actor=actor,
        kind="updated",
        field_changes=field_changes,
        sample_changes=sample_changes,
    )
    if _entry_too_large(entry):
        # The per-sample snapshot is the usual cause (a bulk import), so collapse
        # it to counts first.
        entry.sample_changes = _summarize_sample_changes(sample_changes)
        # Run-level field_changes are normally small, but a few fields (e.g.
        # analyses / pipeline_params) are not hard-capped; if they alone still
        # blow the cap, collapse them too so we never append a doc the
        # best-effort guard would silently drop.
        if field_changes and _entry_too_large(entry):
            entry.field_changes = _summarize_field_changes(field_changes)
    ctx.run_history_repo.append(entry)


def record_run_created(
    ctx: AppContext, run: SequencingRun, actor: str, source: str,
    ref: Optional[str] = None,
) -> None:
    """Append a 'created' anchor entry with provenance."""
    if ctx.run_history_repo is None:
        return
    ctx.run_history_repo.append(RunHistoryEntry(
        run_id=run.id,
        timestamp=run.created_at,
        actor=actor,
        kind="created",
        provenance={"source": source, "ref": ref},
    ))


def record_run_created_safe(
    ctx: AppContext, run: SequencingRun, actor: str, source: str,
    ref: Optional[str] = None,
) -> None:
    """``record_run_created`` for run-creation sites: a history failure must
    never abort run creation, so swallow + log + audit (best-effort, mirroring
    the guard in ``saving_run``)."""
    try:
        record_run_created(ctx, run, actor, source, ref=ref)
    except Exception:
        _log.error(
            "Failed to record %s creation history for run %s",
            source, run.id, exc_info=True,
        )
        audit("run.history.record_failed", actor=actor, target=run.id,
              outcome="failure", reason="create_append_error", source=source)


def cascade_delete_history_safe(ctx: AppContext, run_id: str, actor: str) -> None:
    """Best-effort cascade delete of a run's history on run deletion. A failure
    must never break run deletion, so swallow + log + audit. Orphaned rows keyed
    by an absent run_id are harmless and removable by a reconciliation sweep."""
    if ctx.run_history_repo is None:
        return
    try:
        ctx.run_history_repo.delete_by_run(run_id)
    except Exception:
        _log.error(
            "Failed to cascade-delete history for run %s", run_id, exc_info=True,
        )
        audit("run.history.record_failed", actor=actor, target=run_id,
              outcome="failure", reason="cascade_delete_error")
