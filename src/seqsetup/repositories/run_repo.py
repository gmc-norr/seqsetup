"""Repository for SequencingRun database operations."""

from ..data.instruments import get_default_cycles
from ..models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from .base import BaseRepository


class RunRepository(BaseRepository[SequencingRun]):
    """Repository for managing SequencingRun documents in MongoDB."""

    COLLECTION = "runs"
    MODEL_CLASS = SequencingRun

    def list_by_status(self, status: str) -> list[SequencingRun]:
        """Get all runs with a given status."""
        docs = self.collection.find({"status": status})
        return [SequencingRun.from_dict(doc) for doc in docs]

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
