"""One person edits a Draft run at a time (the user's decision, 2026-10-13).

- **Edit run** takes the run's lock when nobody else's lock is live.
- **Done editing** gives it back; Mark Ready and deleting the run free it.
- **Take over editing** moves it to anyone who asks, whoever held it.
- A page that holds the lock says "still here" every ``BEAT_SECONDS``. A
  lock not seen for ``LIVE_FOR`` counts as free for others, so a closed tab
  does not block the lab -- but it stays its holder's until someone else
  takes it, so coming back to a page nobody touched just works.
- Every change to a Draft needs the lock (``require``), whoever's page sent it.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from ..models.edit_lock import EditLock
from ..utils.clock import local_time, utcnow

BEAT_SECONDS = 60
LIVE_FOR = timedelta(minutes=3)


class EditLockRefused(Exception):
    """The user may not edit the run now; the message says who is."""


@dataclass(frozen=True)
class LockState:
    """What a run's page shows its viewer."""

    lock: Optional[EditLock]
    mine: bool
    someone_else: bool  # another user's lock, seen within LIVE_FOR


def _now(now: Optional[datetime]) -> datetime:
    return now if now is not None else utcnow()


def _live(lock: EditLock, now: datetime) -> bool:
    return lock.seen_at >= now - LIVE_FOR


def _lock(run_id: str, user, now: datetime) -> EditLock:
    return EditLock(run_id=run_id, username=user.username,
                    display_name=user.display_name or user.username,
                    started_at=now, seen_at=now)


def state(repo, run_id: str, username: str, now: Optional[datetime] = None) -> LockState:
    now = _now(now)
    lock = repo.get(run_id)
    mine = lock is not None and lock.username == username
    return LockState(lock=lock, mine=mine,
                     someone_else=lock is not None and not mine and _live(lock, now))


def start(repo, run_id: str, user, now: Optional[datetime] = None) -> EditLock:
    """Edit run. Refused while another user's lock is live."""
    now = _now(now)
    if repo.take(_lock(run_id, user, now), others_seen_before=now - LIVE_FOR):
        return repo.get(run_id)
    holder = repo.get(run_id)
    name = holder.display_name if holder else "Someone"
    since = f" (since {local_time(holder.started_at)})" if holder else ""
    raise EditLockRefused(
        f"{name} is editing this run{since}. If they have left, press Take over editing.")


def take_over(repo, run_id: str, user, now: Optional[datetime] = None) -> Optional[EditLock]:
    """Take over editing, whoever held the run. Returns the lock it replaced."""
    previous = repo.get(run_id)
    repo.replace(_lock(run_id, user, _now(now)))
    return previous


def grant(repo, run_id: str, user, now: Optional[datetime] = None) -> None:
    """Give a run its first editor: a new run's maker, or Back to Draft's."""
    repo.replace(_lock(run_id, user, _now(now)))


def require(repo, run_id: str, username: str, now: Optional[datetime] = None) -> None:
    """Refuse a change unless ``username`` holds the run; mark them seen."""
    if not repo.touch(run_id, username, _now(now)):
        raise EditLockRefused(why_not(repo, run_id))


def why_not(repo, run_id: str) -> str:
    """Why a change from someone who does not hold the run was refused."""
    holder = repo.get(run_id)
    if holder is None:
        return ("You are not editing this run, so nothing was saved. "
                "Reload the page and press Edit run.")
    return (f"{holder.display_name} has been editing this run since "
            f"{local_time(holder.started_at)}, so nothing was saved. Reload the page.")


def lost_message(repo, run_id: str) -> str:
    """What an open edit page says once its lock has gone."""
    holder = repo.get(run_id)
    if holder is None:
        return "You are no longer editing this run. Reload the page: your changes are no longer saved."
    return (f"{holder.display_name} is editing this run now (since {local_time(holder.started_at)}). "
            "Reload the page: your changes are no longer saved.")


def beat(repo, run_id: str, username: str, now: Optional[datetime] = None) -> bool:
    """The page's "still here". False when the lock is no longer theirs."""
    return repo.touch(run_id, username, _now(now))


def end(repo, run_id: str, username: str) -> bool:
    """Done editing: frees the run only when ``username`` holds it."""
    return repo.delete(run_id, username)


def release(repo, run_id: str) -> None:
    """Free the run whoever holds it: it left Draft, or was deleted."""
    repo.delete(run_id)
