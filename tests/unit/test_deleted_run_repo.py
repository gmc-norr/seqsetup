"""Kept copies of deleted runs are only ever added, or moved forward from
pending (spec 2026-09-28 group 2a, F16 + review P1/P2)."""

from datetime import datetime

import mongomock
import pytest
from pymongo.errors import DuplicateKeyError

from seqsetup.models.deleted_run import ABANDONED, COMPLETED, PENDING, DeletedRun
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunStatus, SequencingRun
from seqsetup.repositories.deleted_run_repo import DeletedRunRepository

T0 = datetime(2026, 9, 28, 10, 0, 0)
T1 = datetime(2026, 9, 28, 10, 5, 0)


@pytest.fixture
def repo():
    return DeletedRunRepository(mongomock.MongoClient()["t"])


def _copy(run_id="r1", who="alice", at=T0, samples=("S1",)):
    run = SequencingRun(id=run_id, run_name="Run " + run_id, status=RunStatus.ARCHIVED,
                        created_by="maker")
    for sid in samples:
        run.add_sample(Sample(sample_id=sid))
    run.generated_samplesheet_v2 = "[Header]\nsheet bytes\n"
    return DeletedRun.of(run, who, at)


class TestDeletedRunModel:
    """A copy holds a summary for the list page and the whole run."""

    def test_of_takes_the_summary_and_the_whole_run(self):
        c = _copy()
        assert (c.run_id, c.run_name, c.status, c.sample_count, c.created_by,
                c.deleted_by, c.state) == ("r1", "Run r1", "archived", 1, "maker", "alice", PENDING)
        assert c.run["generated_samplesheet_v2"] == "[Header]\nsheet bytes\n"
        assert c.run_version == c.run["updated_at"]

    def test_round_trip(self):
        c = _copy()
        assert DeletedRun.from_dict(c.to_dict()) == c

    def test_unknown_state_is_refused(self):
        with pytest.raises(ValueError):
            _copy().state = "gone"

    def test_deleted_by_is_capped(self):
        assert len(DeletedRun.of(SequencingRun(id="x"), "u" * 300, T0).deleted_by) == 256


class TestStart:
    """start() inserts; it never replaces an existing copy."""

    def test_start_then_get_returns_the_pending_copy(self, repo):
        c = _copy()
        repo.start(c)
        got = repo.get(c.copy_id)
        assert got.state == PENDING
        assert got.run == c.run

    def test_start_never_replaces(self, repo):
        c = _copy(who="alice")
        repo.start(c)
        clash = _copy(who="mallory")
        clash.copy_id = c.copy_id
        with pytest.raises(DuplicateKeyError):
            repo.start(clash)
        assert repo.get(c.copy_id).deleted_by == "alice"

    def test_two_attempts_for_one_run_are_two_copies(self, repo):
        a, b = _copy(), _copy()
        repo.start(a)
        repo.start(b)
        assert a.copy_id != b.copy_id
        assert repo.get(a.copy_id) is not None and repo.get(b.copy_id) is not None


class TestMoveForwardOnlyFromPending:
    """A completed or abandoned copy can never change again."""

    def test_mark_completed(self, repo):
        c = _copy()
        repo.start(c)
        assert repo.mark_completed(c.copy_id, T1) is True
        got = repo.get(c.copy_id)
        assert (got.state, got.finished_at) == (COMPLETED, T1)

    def test_completed_cannot_be_abandoned_or_completed_again(self, repo):
        c = _copy()
        repo.start(c)
        repo.mark_completed(c.copy_id, T1)
        assert repo.mark_abandoned(c.copy_id, T1, "run_changed") is False
        assert repo.mark_completed(c.copy_id, datetime(2027, 1, 1)) is False
        got = repo.get(c.copy_id)
        assert (got.state, got.finished_at, got.abandon_reason) == (COMPLETED, T1, "")

    def test_abandoned_cannot_be_completed(self, repo):
        c = _copy()
        repo.start(c)
        assert repo.mark_abandoned(c.copy_id, T1, "run_changed") is True
        assert repo.mark_completed(c.copy_id, T1) is False
        got = repo.get(c.copy_id)
        assert (got.state, got.abandon_reason) == (ABANDONED, "run_changed")


class TestListForPage:
    """Summaries only; abandoned copies are never listed."""

    def test_newest_first_without_snapshots_and_without_abandoned(self, repo):
        old, new, dropped = _copy("r1", at=T0), _copy("r2", at=T1), _copy("r3", at=T1)
        for c in (old, new, dropped):
            repo.start(c)
        repo.mark_completed(old.copy_id, T0)
        repo.mark_abandoned(dropped.copy_id, T1, "run_changed")
        rows = repo.list_for_page()
        assert [r["run_id"] for r in rows] == ["r2", "r1"]
        assert all("run" not in r for r in rows)

    def test_list_for_run_reads_one_runs_copies(self, repo):
        mine, other, dropped = _copy("r1"), _copy("r2"), _copy("r1")
        for c in (mine, other, dropped):
            repo.start(c)
        repo.mark_abandoned(dropped.copy_id, T1, "run_changed")
        rows = repo.list_for_run("r1")
        assert [r["copy_id"] for r in rows] == [mine.copy_id]
        assert all("run" not in r for r in rows)
        assert rows[0]["run_version"] == mine.run_version


class TestNoWayToRemoveOrOverwrite:
    def test_no_delete_or_replace_method(self):
        names = {n for n in dir(DeletedRunRepository) if not n.startswith("__")}
        risky = {n for n in names
                 if "delete" in n or "replace" in n or "remove" in n or n in ("save", "upsert")}
        assert risky == set()
