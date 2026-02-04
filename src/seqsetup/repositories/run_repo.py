"""Repository for SequencingRun database operations."""

from typing import Optional

from pymongo.database import Database

from ..data.instruments import get_default_cycles
from ..models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)


class RunRepository:
    """Repository for managing SequencingRun documents in MongoDB."""

    def __init__(self, db: Database):
        self.collection = db["runs"]

    def list_all(self) -> list[SequencingRun]:
        """Get all runs."""
        docs = self.collection.find()
        return [SequencingRun.from_dict(doc) for doc in docs]

    def get_by_id(self, run_id: str) -> Optional[SequencingRun]:
        """Get a run by ID."""
        doc = self.collection.find_one({"_id": run_id})
        if doc:
            return SequencingRun.from_dict(doc)
        return None

    def save(self, run: SequencingRun) -> None:
        """Insert or update a run."""
        self.collection.replace_one(
            {"_id": run.id},
            run.to_dict(),
            upsert=True,
        )

    def list_by_status(self, status: str) -> list[SequencingRun]:
        """Get all runs with a given status."""
        docs = self.collection.find({"status": status})
        return [SequencingRun.from_dict(doc) for doc in docs]

    def delete(self, run_id: str) -> bool:
        """Delete a run by ID."""
        result = self.collection.delete_one({"_id": run_id})
        return result.deleted_count > 0

    def create_run(self, created_by: str = "") -> SequencingRun:
        """Create a new run with default settings and save to database."""
        defaults = get_default_cycles(300)
        run = SequencingRun(
            created_by=created_by,
            updated_by=created_by,
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            reagent_cycles=300,
            run_cycles=RunCycles(
                read1_cycles=defaults["read1"],
                read2_cycles=defaults["read2"],
                index1_cycles=defaults["index1"],
                index2_cycles=defaults["index2"],
            ),
        )
        self.save(run)
        return run
