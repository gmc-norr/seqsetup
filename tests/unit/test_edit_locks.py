"""One person edits a Draft run at a time (the user's decision, 2026-10-13).

The lock is a row in ``edit_locks`` keyed by the run's id. Pressing Edit run
takes it; Done editing gives it back; anyone may take it over. The open page
says "still here" every minute, so a lock not seen for three minutes counts
as free for others -- but it stays its holder's until someone takes it.
"""

from datetime import datetime, timedelta

import mongomock
import pytest

from seqsetup.models.edit_lock import EditLock
from seqsetup.models.user import User, UserRole
from seqsetup.repositories.edit_lock_repo import EditLockRepository
from seqsetup.services import edit_locks
from seqsetup.services.edit_locks import EditLockRefused

T0 = datetime(2026, 10, 13, 12, 0, 0)
ANNA = User(username="anna", display_name="Anna Svensson", role=UserRole.STANDARD)
BEN = User(username="ben", display_name="Ben Berg", role=UserRole.STANDARD)


@pytest.fixture
def repo():
    return EditLockRepository(mongomock.MongoClient()["t"])


def _at(minutes: float) -> datetime:
    return T0 + timedelta(minutes=minutes)


class TestTheModel:
    def test_it_round_trips_with_the_run_id_as_its_id(self):
        lock = EditLock(run_id="r1", username="anna", display_name="Anna Svensson",
                        started_at=T0, seen_at=_at(1))
        doc = lock.to_dict()
        assert doc["_id"] == "r1"
        assert EditLock.from_dict(doc) == lock

    def test_names_are_capped(self):
        lock = EditLock(run_id="r1", username="a" * 300, display_name="b" * 300,
                        started_at=T0, seen_at=T0)
        assert (len(lock.username), len(lock.display_name)) == (256, 256)
        lock.display_name = "c" * 300
        assert len(lock.display_name) == 256


class TestStartingToEdit:
    def test_a_free_run_is_yours(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        lock = repo.get("r1")
        assert (lock.username, lock.display_name, lock.started_at, lock.seen_at) == (
            "anna", "Anna Svensson", T0, T0)

    def test_someone_else_editing_refuses_you_and_names_them(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        with pytest.raises(EditLockRefused) as refused:
            edit_locks.start(repo, "r1", BEN, now=_at(2))
        assert "Anna Svensson is editing this run" in str(refused.value)
        assert repo.get("r1").username == "anna"

    def test_a_lock_not_seen_for_three_minutes_is_free_for_others(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        with pytest.raises(EditLockRefused):
            edit_locks.start(repo, "r1", BEN, now=_at(2.9))
        edit_locks.start(repo, "r1", BEN, now=_at(3.1))
        assert repo.get("r1").username == "ben"

    def test_pressing_it_again_keeps_your_start_time(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        edit_locks.start(repo, "r1", ANNA, now=_at(10))
        lock = repo.get("r1")
        assert (lock.started_at, lock.seen_at) == (T0, _at(10))


class TestSaving:
    def test_the_holder_may_save_and_is_seen(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        edit_locks.require(repo, "r1", "anna", now=_at(1))
        assert repo.get("r1").seen_at == _at(1)

    def test_an_old_lock_is_still_the_holders_until_someone_takes_it(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        edit_locks.require(repo, "r1", "anna", now=_at(30))
        assert repo.get("r1").seen_at == _at(30)

    def test_nobody_editing_refuses_a_save(self, repo):
        with pytest.raises(EditLockRefused) as refused:
            edit_locks.require(repo, "r1", "anna", now=T0)
        assert "You are not editing this run" in str(refused.value)

    def test_someone_else_editing_refuses_a_save_and_names_them(self, repo):
        edit_locks.start(repo, "r1", BEN, now=T0)
        with pytest.raises(EditLockRefused) as refused:
            edit_locks.require(repo, "r1", "anna", now=_at(1))
        assert "Ben Berg has been editing this run since" in str(refused.value)
        assert repo.get("r1").seen_at == T0


class TestTakingOver:
    def test_it_moves_the_lock_and_gives_back_the_old_holder(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        previous = edit_locks.take_over(repo, "r1", BEN, now=_at(1))
        assert previous.username == "anna"
        lock = repo.get("r1")
        assert (lock.username, lock.started_at) == ("ben", _at(1))
        with pytest.raises(EditLockRefused):
            edit_locks.require(repo, "r1", "anna", now=_at(2))

    def test_taking_over_a_free_run_has_no_old_holder(self, repo):
        assert edit_locks.take_over(repo, "r1", BEN, now=T0) is None
        assert repo.get("r1").username == "ben"


class TestTheHeartbeat:
    def test_it_keeps_the_holder_seen(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        assert edit_locks.beat(repo, "r1", "anna", now=_at(1)) is True
        assert repo.get("r1").seen_at == _at(1)

    def test_it_tells_a_page_whose_lock_was_taken(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        edit_locks.take_over(repo, "r1", BEN, now=_at(1))
        assert edit_locks.beat(repo, "r1", "anna", now=_at(2)) is False
        assert repo.get("r1").seen_at == _at(1)


class TestEnding:
    def test_done_editing_frees_the_run(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        assert edit_locks.end(repo, "r1", "anna") is True
        assert repo.get("r1") is None

    def test_done_editing_never_frees_someone_elses_lock(self, repo):
        edit_locks.start(repo, "r1", BEN, now=T0)
        assert edit_locks.end(repo, "r1", "anna") is False
        assert repo.get("r1").username == "ben"

    def test_granting_gives_a_new_run_to_its_maker(self, repo):
        edit_locks.grant(repo, "r1", ANNA, now=T0)
        assert repo.get("r1").username == "anna"

    def test_release_frees_it_whoever_holds_it(self, repo):
        edit_locks.start(repo, "r1", BEN, now=T0)
        edit_locks.release(repo, "r1")
        assert repo.get("r1") is None


class TestWhatAPageShows:
    def test_you_are_editing(self, repo):
        edit_locks.start(repo, "r1", ANNA, now=T0)
        state = edit_locks.state(repo, "r1", "anna", now=_at(30))
        assert (state.mine, state.someone_else, state.lock.username) == (True, False, "anna")

    def test_someone_else_is_editing(self, repo):
        edit_locks.start(repo, "r1", BEN, now=T0)
        state = edit_locks.state(repo, "r1", "anna", now=_at(1))
        assert (state.mine, state.someone_else) == (False, True)

    def test_someone_elses_old_lock_shows_as_free(self, repo):
        edit_locks.start(repo, "r1", BEN, now=T0)
        state = edit_locks.state(repo, "r1", "anna", now=_at(4))
        assert (state.mine, state.someone_else) == (False, False)

    def test_nobody(self, repo):
        state = edit_locks.state(repo, "r1", "anna", now=T0)
        assert (state.mine, state.someone_else, state.lock) == (False, False, None)
