"""The ``run_exports`` collection: one record per file, only ever inserted.

A file is immutable once written, so a manifest that names it always names
the same bytes — that is what lets an archived run, a run sent back to Draft
and a deleted run's kept copy keep pointing at files they never lose. The
repository therefore offers no update and no delete: it does not subclass
BaseRepository, whose ``save`` is an upserting replace
(docs/design/2026-10-16-export-files-own-records-design.md).
"""

import mongomock
import pytest

from seqsetup.repositories.base import BaseRepository
from seqsetup.repositories.run_export_repo import RunExportRepository


@pytest.fixture
def repo():
    return RunExportRepository(mongomock.MongoClient()["t"])


def _doc(**kw):
    doc = {"_id": "a" * 32, "run_id": "r1", "kind": "json", "content": "{}",
           "sha256": "b" * 64, "size": 2, "created_at": "2026-10-16T00:00:00",
           "created_by": "someone"}
    doc.update(kw)
    return doc


class TestTheRepositoryOnlyInserts:

    def test_it_is_not_a_base_repository(self):
        """BaseRepository.save upserts a replace and BaseRepository.delete
        removes by id: either would break the insert-only rule."""
        assert not issubclass(RunExportRepository, BaseRepository)

    def test_it_offers_only_insert_and_get(self):
        public = {n for n in dir(RunExportRepository) if not n.startswith("_")}
        assert public == {"COLLECTION", "insert", "get"}

    def test_an_inserted_file_comes_back_byte_for_byte(self, repo):
        repo.insert(_doc(content="a,b\n1,2\n"))
        assert repo.get("a" * 32)["content"] == "a,b\n1,2\n"

    def test_a_pdf_comes_back_as_bytes(self, repo):
        repo.insert(_doc(kind="validation_pdf", content=b"%PDF-1.4\n\x00\xff"))
        assert repo.get("a" * 32)["content"] == b"%PDF-1.4\n\x00\xff"

    def test_an_id_that_is_not_there_gives_none(self, repo):
        assert repo.get("c" * 32) is None

    def test_a_second_insert_of_the_same_id_is_refused(self, repo):
        repo.insert(_doc(content="first"))
        with pytest.raises(Exception):
            repo.insert(_doc(content="second"))
        assert repo.get("a" * 32)["content"] == "first"

    def test_it_writes_into_the_run_exports_collection(self, repo):
        assert RunExportRepository.COLLECTION == "run_exports"
        repo.insert(_doc())
        assert repo.collection.name == "run_exports"


class TestTheRepositoryIsRequired:
    """A missing repository must not let a reader fall through to another
    path: it is in the registry and on the context, not Optional."""

    def test_the_registry_builds_it(self):
        from seqsetup.startup import _REPO_REGISTRY
        assert _REPO_REGISTRY["run_export"] is RunExportRepository

    def test_the_context_requires_it(self):
        import dataclasses
        from seqsetup.context import AppContext
        field = {f.name: f for f in dataclasses.fields(AppContext)}["run_export_repo"]
        assert field.default is dataclasses.MISSING, "an optional repository can be None"
        assert "Optional" not in str(field.type)
