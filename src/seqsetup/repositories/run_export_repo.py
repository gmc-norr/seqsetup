"""Repository for a Ready run's export files: one record per file.

Deliberately NOT a ``BaseRepository`` subclass. That base offers ``save``
(an upserting replace) and ``delete`` (by id), and either would break the one
rule this collection rests on: a file record is only ever inserted. A file
is immutable once written, so a manifest that names it always names the same
bytes — which is what lets an archived run, a run sent back to Draft and a
deleted run's kept copy keep pointing at files they never lose.

Records of a Mark Ready that then failed, and of a deleted run's copy, look
unreferenced. They are not pruned: see docs/getting-started/deployment.rst.
"""

from typing import Optional

from pymongo.database import Database


class RunExportRepository:
    """Thin data layer over ``run_exports``: insert a file, read one back."""

    COLLECTION = "run_exports"

    def __init__(self, db: Database):
        self.collection = db[self.COLLECTION]
        # The app reads a file by its id only. The collection only grows and
        # is never pruned, so an operator looking up one run's files by hand
        # must not make the database read every file.
        self.collection.create_index("run_id")

    def insert(self, doc: dict) -> None:
        """Insert one file record. Raises if its ``_id`` is already there."""
        self.collection.insert_one(doc)

    def get(self, file_id: str) -> Optional[dict]:
        """One file record by id, or None."""
        return self.collection.find_one({"_id": file_id})
