"""What Admin → Deleted runs shows (spec 2026-09-28 group 2a, F16, both reviews).

Decided when the page is read, from each copy's state and whether its run
still exists, so a delete that did not finish never looks finished. At most
one row per run:

- a completed copy                     -> that copy, "Deleted"
- only pending copies, run still there -> no row (nothing was deleted, or a
                                          delete is still under way)
- only pending copies, run gone        -> that run's copies are read again,
  now that the run is seen gone (a delete may have finished meanwhile). A
  completed copy there -> "Deleted". Otherwise one row, "Deleted — not
  confirmed": the pending copy of the newest run version, naming every user
  whose attempt saw that version.
- abandoned copies                     -> never listed

Why the newest version: a delete matches only the version stored at that
moment, and a deleted run gets no newer version, so the attempt that deleted
the run checked the newest version any attempt saw. Attempts on that same
version hold the same run; which of them deleted it is not known, so all are
named.

Read only: nothing here changes a copy or a run.
"""

from typing import Optional

from ..models.deleted_run import COMPLETED, PENDING, DeletedRun

DELETED = "Deleted"
NOT_CONFIRMED = "Deleted — not confirmed"


def _deleted_row(row: dict) -> dict:
    return {**row, "shown_state": DELETED, "shown_deleted_by": row["deleted_by"]}


def _not_confirmed_row(pending: list[dict]) -> dict:
    newest = max(row["run_version"] for row in pending)
    same_version = [row for row in pending if row["run_version"] == newest]
    shown = max(same_version, key=lambda row: (row["started_at"], row["copy_id"]))
    names = " or ".join(sorted({row["deleted_by"] for row in same_version}))
    return {**shown, "shown_state": NOT_CONFIRMED, "shown_deleted_by": names}


def visible_rows(deleted_run_repo, run_repo) -> list[dict]:
    """The page's rows, at most one per run, newest first."""
    rows = deleted_run_repo.list_for_page()
    shown: dict[str, dict] = {}
    for row in rows:
        if row["state"] == COMPLETED:
            shown[row["run_id"]] = _deleted_row(row)
    unfinished = []
    for row in rows:
        if row["state"] == PENDING and row["run_id"] not in shown and row["run_id"] not in unfinished:
            unfinished.append(row["run_id"])
    for run_id in unfinished:
        if run_repo.get_by_id(run_id) is not None:
            continue
        # Read this run's copies again now that the run is seen gone
        # (second review, P2).
        fresh = deleted_run_repo.list_for_run(run_id)
        completed = [row for row in fresh if row["state"] == COMPLETED]
        pending = [row for row in fresh if row["state"] == PENDING]
        if completed:
            shown[run_id] = _deleted_row(completed[0])
        elif pending:
            shown[run_id] = _not_confirmed_row(pending)
    return sorted(shown.values(), key=lambda row: (row["started_at"], row["copy_id"]), reverse=True)


def visible_copy(deleted_run_repo, run_repo, copy_id: str) -> Optional[tuple[DeletedRun, dict]]:
    """The copy and its row if the list shows it, else None."""
    for row in visible_rows(deleted_run_repo, run_repo):
        if row["copy_id"] == copy_id:
            copy = deleted_run_repo.get(copy_id)
            return (copy, row) if copy is not None else None
    return None
