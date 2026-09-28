"""Deleting a run keeps a copy and its history (spec 2026-09-28 group 2a,
F16 + review P1/P2).

A run that was ever Ready is copied before it is deleted; only the exact
version that was checked is deleted; the copy moves pending -> completed or
abandoned; change history is never deleted."""

from datetime import datetime, timedelta

import pytest
from starlette.testclient import TestClient

from seqsetup.models.local_user import LocalUser
from seqsetup.models.run_history import RunHistoryEntry
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunStatus
from seqsetup.models.user import UserRole

from .conftest import disable_repos

ORIGIN = {"Origin": "http://testserver"}
HX = {**ORIGIN, "HX-Request": "true"}
RUN_CHANGED = "Someone else changed or deleted this run at the same moment"


class TestWiring:
    def test_the_copy_store_is_wired(self, fresh_app):
        from seqsetup.repositories.deleted_run_repo import DeletedRunRepository
        _app, ctx, _db = fresh_app
        assert isinstance(ctx.deleted_run_repo, DeletedRunRepository)
