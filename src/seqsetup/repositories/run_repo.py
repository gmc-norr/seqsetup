"""Repository for SequencingRun database operations."""

from ..data.instruments import get_default_cycles
from ..models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from .base import BaseRepository, ConflictError


class RunRepository(BaseRepository[SequencingRun]):
    """Repository for managing SequencingRun documents in MongoDB."""

    COLLECTION = "runs"
    MODEL_CLASS = SequencingRun
    # The instrument a new run starts on.
    NEW_RUN_INSTRUMENT = InstrumentPlatform.NOVASEQ_X

    def list_by_status(self, status: str) -> list[SequencingRun]:
        """Get all runs with a given status."""
        docs = self.collection.find({"status": status})
        return [SequencingRun.from_dict(doc) for doc in docs]

    def save(self, run: SequencingRun) -> None:
        """Insert or update a run with optimistic-locking on updated_at.

        First save (never loaded — ``_loaded_updated_at is None``) uses an
        unconditional upsert so brand-new runs work as before.

        Subsequent saves filter on the load-time updated_at. If a concurrent
        edit has bumped the stored updated_at since this instance was loaded,
        ``matched_count == 0`` and ConflictError is raised — silently
        overwriting the concurrent edit would lose clinical data.

        On success, ``_loaded_updated_at`` is moved forward to the new
        updated_at so the next save of the same instance still has a valid
        version token.
        """
        item_id = self._get_id(run)
        doc = run.to_dict()
        doc["_id"] = item_id

        if run._loaded_updated_at is None:
            # First-time insert (or unloaded fresh instance) — upsert.
            self.collection.replace_one({"_id": item_id}, doc, upsert=True)
            run._loaded_updated_at = run.updated_at
            return

        # Optimistic-lock check: stored updated_at must match the one we read.
        expected = run._loaded_updated_at.isoformat()
        result = self.collection.replace_one(
            {"_id": item_id, "updated_at": expected},
            doc,
            upsert=False,
        )
        if result.matched_count == 0:
            # Either the doc was deleted or its updated_at no longer matches.
            current = self.collection.find_one({"_id": item_id}, {"updated_at": 1})
            if current is None:
                raise ConflictError(
                    f"Run {item_id} was deleted while you were editing it"
                )
            raise ConflictError(
                f"Run {item_id} was modified by another user since you loaded it "
                f"(expected updated_at={expected}, "
                f"now {current.get('updated_at')!r}). "
                f"Refresh to see the latest version and reapply your changes."
            )
        run._loaded_updated_at = run.updated_at

    def delete_if_unchanged(self, run: SequencingRun) -> bool:
        """Delete ``run`` only if the stored version is the one that was loaded.

        Returns True if it was deleted, False if nothing matched (the run was
        changed or deleted since it was loaded). Never falls back to an
        id-only delete (spec 2026-09-28 group 2a, review P1).
        """
        if run._loaded_updated_at is None:
            raise ValueError(
                f"Run {run.id} was never loaded; refusing to delete it without a version check"
            )
        result = self.collection.delete_one(
            {"_id": run.id, "updated_at": run._loaded_updated_at.isoformat()}
        )
        return result.deleted_count == 1

    def create_run(self, created_by: str = "", i5_workflow: str = "") -> SequencingRun:
        """Create a new run with default settings and save to database.

        ``i5_workflow`` is NEW_RUN_INSTRUMENT's standard i5 workflow, or ""
        when it has no settings; the caller looks it up, so the run is saved
        once, with it (spec 2026-10-04 group A2, §3).
        """
        defaults = get_default_cycles(300)
        run = SequencingRun(
            created_by=created_by,
            updated_by=created_by,
            instrument_platform=self.NEW_RUN_INSTRUMENT,
            flowcell_type="10B",
            reagent_cycles=300,
            i5_workflow=i5_workflow,
            run_cycles=RunCycles(
                read1_cycles=defaults["read1"],
                read2_cycles=defaults["read2"],
                index1_cycles=defaults["index1"],
                index2_cycles=defaults["index2"],
            ),
        )
        self.save(run)
        return run
