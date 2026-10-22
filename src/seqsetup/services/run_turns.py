"""One run's edits, one at a time.

Every route is a plain ``def``, which Starlette runs on a worker thread, so a
slow save no longer stops the app for everyone (project review F9). The one
event loop used to line up one person's quick saves to a run by accident --
two row boxes saved a split second apart, a row save and a bulk Apply, two
tabs. On worker threads they overlap, and the second would load the run before
the first had saved it and then lose the run's version check: "modified by
another user", for the person's own edit.

So each request that edits a run waits its turn for that run here, on the
event loop, before it loads the run (``get_editable_run`` in
``routes/dependencies.py``). Turns are given in the order they were asked
for. They are per run: an edit of another run never waits. The app is one
process with one event loop, so one table covers every request, as
``_SYNC_LOCK`` does for the configuration sync. A turn that does not come
within ``TURN_WAIT_SECONDS`` is refused, never waited for without end.

Mark Ready takes no turn: it may run for minutes, and it already refuses a
run that changed while its files were written.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

# A save takes well under a second; the database gives up on a socket after
# 30. Longer than that, something is stuck.
TURN_WAIT_SECONDS = 60.0

TURN_REFUSED = (
    "Another change to this run is still being saved, so this one was not. "
    "Nothing was changed. Try again in a moment."
)


class TurnNotGiven(Exception):
    """The run's turn did not come within ``TURN_WAIT_SECONDS``."""


# run id -> [its lock, how many requests hold or wait for it]. An entry goes
# when the last of them is done, so the table holds only runs being edited.
_turns: dict[str, list] = {}


@asynccontextmanager
async def turn(run_id: str) -> AsyncIterator[None]:
    """Hold ``run_id``'s turn for the body of the ``async with``."""
    entry = _turns.get(run_id)
    if entry is None:
        entry = _turns[run_id] = [asyncio.Lock(), 0]
    entry[1] += 1
    try:
        try:
            async with asyncio.timeout(TURN_WAIT_SECONDS):
                await entry[0].acquire()
        except TimeoutError:
            raise TurnNotGiven(TURN_REFUSED) from None
        try:
            yield
        finally:
            entry[0].release()
    finally:
        entry[1] -= 1
        if entry[1] == 0 and _turns.get(run_id) is entry:
            del _turns[run_id]
