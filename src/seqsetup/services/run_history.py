"""Recording helpers for per-run change history.

Invoked from saving_run (edits) and the creation sites. All callers wrap these
in their own try/except so a history failure never breaks a persisted clinical
edit (the deployment's standalone MongoDB has no transactions; the run save and
the history append are separate writes — best-effort by necessity).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from ..models.run_history import RunHistoryEntry
from .audit_log import audit
from .run_diff import diff_run, is_empty

if TYPE_CHECKING:
    from ..context import AppContext
    from ..models.sequencing_run import SequencingRun

_log = logging.getLogger(__name__)


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
    ctx.run_history_repo.append(RunHistoryEntry(
        run_id=run.id,
        timestamp=run.updated_at,
        actor=actor,
        kind="updated",
        field_changes=field_changes,
        sample_changes=sample_changes,
    ))


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
