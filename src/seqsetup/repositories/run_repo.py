"""Repository for SequencingRun database operations."""

import logging
import re
from datetime import datetime
from typing import Optional

from ..data.instruments import get_default_cycles
from ..models.run_listing import RunListing
from ..models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    RunStatus,
    SequencingRun,
)
from ..utils.clock import utcnow
from .base import BaseRepository, ConflictError


logger = logging.getLogger(__name__)


class RunRepository(BaseRepository[SequencingRun]):
    """Repository for managing SequencingRun documents in MongoDB."""

    COLLECTION = "runs"
    MODEL_CLASS = SequencingRun
    # The instrument a new run starts on.
    NEW_RUN_INSTRUMENT = InstrumentPlatform.NOVASEQ_X

    def list_all_readable(self) -> tuple[list[SequencingRun], list[str]]:
        """Every run whose document loads, and the ids of the ones that do not.

        The inherited ``list_all`` builds every document with no per-document
        guard, so one document this release cannot read — a whole-number
        field stored as 1.0, a base no index allows, an analysis type it does
        not know, all of which only a direct database write or an older
        release produces — raises for the whole listing. A page that lists
        runs cannot be reached at all then, not even for the runs that are
        fine.

        The unreadable ids come back with the runs so the caller can name
        them: one is never dropped silently (CLAUDE.md: never silently
        discard data). Each is logged at WARNING with what stopped it, for
        the administrator who has to repair the document. Nothing is written.

        ``list_all`` and ``list_by_status`` are left exactly as they are:
        every other repository shares ``list_all``, and ``list_by_status``
        serves ``/api/runs``, where a quietly shortened list would change
        what an external clinical consumer receives.
        """
        runs: list[SequencingRun] = []
        unreadable: list[str] = []
        for doc in self.collection.find():
            try:
                runs.append(SequencingRun.from_dict(doc))
            except Exception as exc:
                run_id = str(doc.get("_id") or "") or "(a run document with no id)"
                logger.warning("Run %s could not be read: %s", run_id, exc)
                unreadable.append(run_id)
        return runs, unreadable

    def list_by_status(self, status: str) -> list[SequencingRun]:
        """Get all runs with a given status."""
        docs = self.collection.find({"status": status})
        return [SequencingRun.from_dict(doc) for doc in docs]

    # ----------------------------------------------------------------
    # Listings: a row at a time, never a whole run
    # (docs/design/2026-10-17-listing-summaries-design.md)
    # ----------------------------------------------------------------

    def _listing_pipeline(
        self,
        match: Optional[dict] = None,
        *,
        newest_first: bool = False,
        limit: Optional[int] = None,
        skip: int = 0,
        with_sample_ids: bool = False,
    ) -> list[dict]:
        """The stages that build listing rows in the database.

        The sort key is the stored ``updated_at``, or now when a document has
        none — which is what ``SequencingRun.from_dict`` gives such a run, so
        the order is the one the whole-run listings produced.
        """
        projection = RunListing.projection(with_sample_ids=with_sample_ids)
        projection["_listing_sort"] = {"$ifNull": ["$updated_at", utcnow().isoformat()]}
        pipeline: list[dict] = []
        if match is not None:
            pipeline.append({"$match": match})
        pipeline.append({"$project": projection})
        if newest_first:
            pipeline.append({"$sort": {"_listing_sort": -1}})
        if skip:
            pipeline.append({"$skip": skip})
        if limit is not None:
            pipeline.append({"$limit": limit})
        return pipeline

    def list_summaries(
        self,
        status: Optional[str] = None,
        *,
        newest_first: bool = False,
        limit: Optional[int] = None,
        skip: int = 0,
    ) -> list[RunListing]:
        """Listing rows, without loading a single sample.

        Raises on a document whose row cannot be built, exactly as
        ``list_by_status`` does: this serves ``GET /api/runs`` and
        ``/served-runs``, where a quietly shortened list would change what an
        external clinical consumer receives.

        ``status`` is matched as stored, so the legacy ``"complete"`` is not
        an ``"archived"`` run here — again exactly as ``list_by_status``.
        """
        pipeline = self._listing_pipeline(
            {"status": status} if status is not None else None,
            newest_first=newest_first, limit=limit, skip=skip,
        )
        return [RunListing.from_doc(doc) for doc in self.collection.aggregate(pipeline)]

    def list_readable_summaries(self) -> tuple[list[RunListing], list[str]]:
        """Every run as a listing row, and the ids of the ones that do not
        read — the dashboard's pair, matching ``list_all_readable``.

        A row that cannot be built is named, never dropped (CLAUDE.md: never
        silently discard data). A row reads none of the samples, so a run
        whose samples cannot be read is listed here and fails when it is
        opened, which is the one behaviour this change alters (see the design
        note).
        """
        listings: list[RunListing] = []
        unreadable: list[str] = []
        for doc in self.collection.aggregate(self._listing_pipeline()):
            try:
                listings.append(RunListing.from_doc(doc))
            except Exception as exc:
                run_id = str(doc.get("_id") or "") or "(a run document with no id)"
                logger.warning("Run %s could not be listed: %s", run_id, exc)
                unreadable.append(run_id)
        return listings, unreadable

    def search_summaries(self, query: str) -> tuple[list[RunListing], dict[str, list[str]]]:
        """Runs whose name, or any sample ID, contains ``query`` (ignoring
        case), newest first, and for each the sample IDs that matched.

        The match is made in the database, over a projection that reads one
        field of each sample — ``sample_id``, the field it matches on — and
        nothing else. ``query`` is escaped, so it is a plain substring as it
        was when the search ran in Python.
        """
        pattern = re.escape(query)
        match = {"$or": [
            {"run_name": {"$regex": pattern, "$options": "i"}},
            {"samples.sample_id": {"$regex": pattern, "$options": "i"}},
        ]}
        pipeline = self._listing_pipeline(match, newest_first=True, with_sample_ids=True)
        listings: list[RunListing] = []
        matched: dict[str, list[str]] = {}
        lowered = query.lower()
        for doc in self.collection.aggregate(pipeline):
            try:
                listing = RunListing.from_doc(doc)
            except Exception as exc:
                # A row that cannot be built is left out of the results, as
                # it was when the search ran over list_all_readable. It is
                # not lost: the search page lists every unreadable run id
                # above the results, from list_readable_summaries.
                run_id = str(doc.get("_id") or "") or "(a run document with no id)"
                logger.warning("Run %s could not be listed: %s", run_id, exc)
                continue
            listings.append(listing)
            matched[listing.id] = [
                sample.get("sample_id") for sample in (doc.get("samples") or [])
                if lowered in (sample.get("sample_id") or "").lower()
            ]
        return listings, matched

    def count_summaries(self, status: Optional[str] = None) -> int:
        """How many runs a listing of ``status`` would have, counted in the
        database — no document is read."""
        return self.collection.count_documents({"status": status} if status is not None else {})

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
        self._refuse_a_listing(run, "saved")
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

    @staticmethod
    def _refuse_a_listing(run, what: str) -> None:
        """A listing row is not a run and must never be written as one.

        ``RunListing`` holds no samples and no export manifest, so writing
        one back would erase a Ready run's stored Sample Sheet. The guard is
        here, in the repository, so no caller has to remember
        (docs/design/2026-10-17-listing-summaries-design.md).
        """
        if not isinstance(run, SequencingRun):
            raise TypeError(
                f"{type(run).__name__} is not a SequencingRun and cannot be {what}; "
                f"a listing row holds no samples and no export manifest"
            )

    def mark_changed(self, run_id: str, when: datetime, by: str) -> bool:
        """Move a Draft's stored version (``updated_at``) on without changing
        its content, so a save of a copy loaded before now is refused by the
        version check in ``save``. A run no longer a Draft is left as it is."""
        result = self.collection.update_one(
            {"_id": run_id, "status": RunStatus.DRAFT.value},
            {"$set": {"updated_at": when.isoformat(), "updated_by": by}},
        )
        return result.matched_count == 1

    def delete(self, item_id: str) -> bool:
        """Refuse an id-only delete: it would skip the version check.

        A run is deleted only through ``delete_if_unchanged``, so the
        version that was checked is the version that goes (spec 2026-09-28
        group 2a, review P1). Other repositories keep the inherited delete.
        """
        raise ValueError(
            f"Run {item_id} cannot be deleted by id alone; "
            f"refusing to delete it without a version check"
        )

    def delete_if_unchanged(self, run: SequencingRun, *, copy_id: str = "") -> bool:
        """Delete ``run`` only if the stored version is the one that was loaded.

        Returns True if it was deleted, False if nothing matched (the run was
        changed or deleted since it was loaded). Never falls back to an
        id-only delete (spec 2026-09-28 group 2a, review P1).

        ``copy_id`` is the id of the copy kept for this run. A run that was
        ever Ready is not deleted without it, so this call cannot delete such
        a run without being told where its copy is (spec 2026-09-28 group 2a,
        F16). Which runs may be deleted, and by whom, stays in the route.
        """
        self._refuse_a_listing(run, "deleted")
        if run._loaded_updated_at is None:
            raise ValueError(
                f"Run {run.id} was never loaded; refusing to delete it without a version check"
            )
        if run.was_ready and not copy_id:
            raise ValueError(
                f"Run {run.id} was Ready once; refusing to delete it without the id of "
                f"the copy kept for it"
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
