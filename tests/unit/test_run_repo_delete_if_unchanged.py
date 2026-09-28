"""RunRepository.delete_if_unchanged deletes only the version that was
loaded (spec 2026-09-28 group 2a, review P1)."""

from datetime import timedelta

import mongomock
import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import SequencingRun
from seqsetup.repositories.run_repo import RunRepository


@pytest.fixture
def repo():
    return RunRepository(mongomock.MongoClient()["t"])


def _loaded(repo, run_id="r1"):
    repo.save(SequencingRun(id=run_id, run_name="R"))
    return repo.get_by_id(run_id)


class TestDeleteIfUnchanged:
    """The version check that save() already uses, applied to delete."""

    def test_deletes_the_loaded_version(self, repo):
        run = _loaded(repo)
        assert repo.delete_if_unchanged(run) is True
        assert repo.get_by_id("r1") is None

    def test_refuses_when_the_run_changed(self, repo):
        run = _loaded(repo)
        other = repo.get_by_id("r1")
        other.add_sample(Sample(sample_id="LATE"))
        other.updated_at = other.updated_at + timedelta(seconds=1)
        repo.save(other)
        assert repo.delete_if_unchanged(run) is False
        assert [s.sample_id for s in repo.get_by_id("r1").samples] == ["LATE"]

    def test_false_when_already_gone(self, repo):
        run = _loaded(repo)
        repo.collection.delete_one({"_id": "r1"})
        assert repo.delete_if_unchanged(run) is False

    def test_never_loaded_run_is_refused(self, repo):
        with pytest.raises(ValueError):
            repo.delete_if_unchanged(SequencingRun(id="r2"))
