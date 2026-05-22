"""Tests for optimistic-locking on RunRepository.save().

Two concurrent edits on the same DRAFT run would previously silently
overwrite each other — the lost edit was invisible to both users. The
``updated_at`` value loaded with the run is now used as a version token:
a save whose load-time updated_at no longer matches the stored value
raises ConflictError.
"""

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from seqsetup.models.sequencing_run import InstrumentPlatform, SequencingRun
from seqsetup.repositories.base import ConflictError
from seqsetup.repositories.run_repo import RunRepository


def _make_repo_with_collection(collection_mock):
    """Construct a RunRepository whose .collection is the given mock."""
    repo = RunRepository.__new__(RunRepository)
    repo.collection = collection_mock
    return repo


class TestFreshInsert:
    """A run that has never been loaded saves unconditionally (upsert)."""

    def test_fresh_run_upserts_without_version_filter(self):
        coll = MagicMock()
        coll.replace_one.return_value = MagicMock(matched_count=1)
        repo = _make_repo_with_collection(coll)

        run = SequencingRun(
            id="run-1",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
        )
        # Freshly constructed — no _loaded_updated_at yet.
        assert run._loaded_updated_at is None

        repo.save(run)

        # Filter is {_id: ...} only — no updated_at gate.
        args, kwargs = coll.replace_one.call_args
        assert args[0] == {"_id": "run-1"}
        assert kwargs.get("upsert") is True
        # After save, _loaded_updated_at is captured so subsequent saves can lock.
        assert run._loaded_updated_at == run.updated_at


class TestLockedUpdate:
    """A loaded run's save uses the load-time updated_at as a version token."""

    def _loaded_run(self, updated_at: datetime) -> SequencingRun:
        """Simulate a from_dict-ed run with a known load-time updated_at."""
        run = SequencingRun(id="run-1", updated_at=updated_at)
        run._loaded_updated_at = updated_at
        return run

    def test_save_filters_on_loaded_updated_at(self):
        loaded_at = datetime(2026, 5, 1, 10, 0, 0)
        coll = MagicMock()
        coll.replace_one.return_value = MagicMock(matched_count=1)
        repo = _make_repo_with_collection(coll)

        run = self._loaded_run(loaded_at)
        # Simulate the route flow: touch bumps in-memory updated_at, then save.
        new_time = datetime(2026, 5, 1, 10, 5, 0)
        run.updated_at = new_time

        repo.save(run)

        args, _ = coll.replace_one.call_args
        # Filter must include the LOAD-TIME updated_at, not the new one.
        assert args[0] == {"_id": "run-1", "updated_at": loaded_at.isoformat()}
        # After success, the lock token advances to the new updated_at.
        assert run._loaded_updated_at == new_time

    def test_conflict_when_matched_count_zero_and_doc_exists(self):
        loaded_at = datetime(2026, 5, 1, 10, 0, 0)
        coll = MagicMock()
        coll.replace_one.return_value = MagicMock(matched_count=0)
        # A concurrent writer has bumped the stored updated_at.
        coll.find_one.return_value = {"updated_at": "2026-05-01T10:01:23.000000"}
        repo = _make_repo_with_collection(coll)

        run = self._loaded_run(loaded_at)
        run.updated_at = datetime(2026, 5, 1, 10, 5, 0)

        with pytest.raises(ConflictError, match="modified by another user"):
            repo.save(run)

    def test_conflict_when_doc_deleted(self):
        loaded_at = datetime(2026, 5, 1, 10, 0, 0)
        coll = MagicMock()
        coll.replace_one.return_value = MagicMock(matched_count=0)
        coll.find_one.return_value = None  # Document is gone.
        repo = _make_repo_with_collection(coll)

        run = self._loaded_run(loaded_at)
        with pytest.raises(ConflictError, match="deleted"):
            repo.save(run)

    def test_load_time_token_not_advanced_on_conflict(self):
        loaded_at = datetime(2026, 5, 1, 10, 0, 0)
        coll = MagicMock()
        coll.replace_one.return_value = MagicMock(matched_count=0)
        coll.find_one.return_value = {"updated_at": "2026-05-01T10:01:23.000000"}
        repo = _make_repo_with_collection(coll)

        run = self._loaded_run(loaded_at)
        with pytest.raises(ConflictError):
            repo.save(run)
        # _loaded_updated_at must NOT advance on a failed save — otherwise a
        # subsequent retry would silently succeed against the wrong baseline.
        assert run._loaded_updated_at == loaded_at


class TestModelLoadCapturesLockToken:
    """from_dict must populate _loaded_updated_at so save can lock against it."""

    def test_from_dict_sets_loaded_updated_at(self):
        data = {
            "id": "run-1",
            "updated_at": "2026-05-01T10:00:00",
        }
        run = SequencingRun.from_dict(data)
        assert run._loaded_updated_at == datetime(2026, 5, 1, 10, 0, 0)
        assert run.updated_at == run._loaded_updated_at

    def test_touch_does_not_mutate_loaded_token(self):
        run = SequencingRun.from_dict(
            {"id": "run-1", "updated_at": "2026-05-01T10:00:00"}
        )
        loaded = run._loaded_updated_at
        run.touch(updated_by="alice")
        # in-memory updated_at moves forward; the lock token stays put.
        assert run.updated_at > loaded
        assert run._loaded_updated_at == loaded

    def test_to_dict_does_not_emit_loaded_updated_at(self):
        """The lock token is runtime-only state; it must not be persisted."""
        run = SequencingRun.from_dict(
            {"id": "run-1", "updated_at": "2026-05-01T10:00:00"}
        )
        assert "_loaded_updated_at" not in run.to_dict()
