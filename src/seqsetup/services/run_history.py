"""Recording helpers for per-run change history.

Invoked from saving_run (edits) and the creation sites. All callers wrap these
in their own try/except so a history failure never breaks a persisted clinical
edit (the deployment's standalone MongoDB has no transactions; the run save and
the history append are separate writes — best-effort by necessity).
"""

from ..models.run_history import RunHistoryEntry
from .run_diff import diff_run, is_empty


def record_run_updated(ctx, run, before: dict, actor: str) -> None:
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


def record_run_created(ctx, run, actor: str, source: str, ref=None) -> None:
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
