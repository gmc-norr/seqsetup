"""Smoke tests for validation and status transitions.

These cover the clinically-sensitive paths:
- Mark Ready refuses a run with validation errors (live check).
- Mark Ready succeeds and pre-generates exports for a clean run.
- Optimistic locking surfaces as 409.
- ARCHIVED is terminal.
"""

import pytest

from .conftest import disable_repos, mark_ready
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    RunStatus,
    SequencingRun,
)


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _make_ready_eligible_run(ctx, run_id: str = None) -> str:
    """Set up a run that should be mark-ready eligible: has samples, all have indexes.

    Samples have no test_id, and we null the profile repos on ctx AND on
    the startup module's repo cache — this forces validation to use the
    hardcoded BCLConvert path and skip the application-profile lookup that
    would otherwise fail with test_profile_not_found for un-seeded test
    types.
    """
    disable_repos(ctx, "test_profile", "app_profile")

    run = SequencingRun(
        id=run_id or "smoke-validation-run",
        run_name="Smoke Validation",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(Sample(
        sample_id="S1",
        index_pair=IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
    ))
    run.add_sample(Sample(
        sample_id="S2",
        index_pair=IndexPair(
            id="p2", name="p2",
            index1=Index(name="i7b", sequence="TCCGGAGA", index_type=IndexType.I7),
            index2=Index(name="i5b", sequence="ATAGAGGC", index_type=IndexType.I5),
        ),
    ))
    ctx.run_repo.save(run)
    return run.id


class TestValidationPage:
    def test_validation_page_renders(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx)

        response = logged_in_client.get(f"/runs/{run_id}/validation")
        assert response.status_code == 200


class TestMarkReady:
    def test_mark_ready_refuses_run_with_no_samples(self, logged_in_client, fresh_app):
        """Mark Ready refuses an empty run with a real-time validation error."""
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = SequencingRun(
            id="empty-run",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
        )
        ctx.run_repo.save(run)

        response = logged_in_client.post(
            "/runs/empty-run/status/ready",
            headers=_origin(),
        )
        assert response.status_code == 200
        # Body contains an error about samples or validation
        body_lower = response.text.lower()
        assert "sample" in body_lower or "error" in body_lower
        # HX-Retarget is set so the message lands in #ready-message
        assert response.headers.get("HX-Retarget") == "#ready-message"
        # Status stays DRAFT
        assert ctx.run_repo.get_by_id("empty-run").status == RunStatus.DRAFT

    def test_mark_ready_succeeds_for_clean_run(self, logged_in_client, fresh_app):
        """Mark Ready transitions status and pre-generates exports for a valid run."""
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx)

        response = mark_ready(logged_in_client, run_id, _origin())
        assert response.status_code == 200

        updated = ctx.run_repo.get_by_id(run_id)
        assert updated.status == RunStatus.READY
        # Exports were pre-generated.
        assert updated.generated_samplesheet_v2 is not None
        assert "[BCLConvert_Data]" in updated.generated_samplesheet_v2
        assert updated.generated_json is not None


class TestStatusTransition:
    def test_archived_is_terminal(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = SequencingRun(
            id="archived-run",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            status=RunStatus.ARCHIVED,
        )
        ctx.run_repo.save(run)

        # Try to bring it back to DRAFT.
        response = logged_in_client.post(
            "/runs/archived-run/status/draft",
            headers=_origin(),
        )
        assert response.status_code == 400
        assert ctx.run_repo.get_by_id("archived-run").status == RunStatus.ARCHIVED


class TestOptimisticLockRealPath:
    """End-to-end exercise of the actual ``matched_count == 0`` path —
    not just the exception handler. We mutate the stored updated_at out
    from under a route's loaded copy, then attempt to save: the repo
    layer must raise ConflictError, which the exception handler turns
    into a 409."""

    def test_stored_updated_at_drift_produces_409(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx)

        original_get = ctx.run_repo.get_by_id
        mutated = {"done": False}

        def get_then_mutate(rid):
            run = original_get(rid)
            if not mutated["done"] and run is not None and rid == run_id:
                from datetime import datetime, timedelta
                future = (datetime.now() + timedelta(minutes=1)).isoformat()
                ctx.run_repo.collection.update_one(
                    {"_id": rid},
                    {"$set": {"updated_at": future}},
                )
                mutated["done"] = True
            return run

        ctx.run_repo.get_by_id = get_then_mutate
        try:
            response = logged_in_client.post(
                f"/runs/{run_id}/name",
                data={"run_name": "Loser's Edit"},
                headers=_origin(),
            )
        finally:
            ctx.run_repo.get_by_id = original_get

        assert response.status_code == 409, (
            f"Expected 409 from the real optimistic-lock path; "
            f"got {response.status_code} body={response.text[:200]}"
        )
        assert "modified" in response.text.lower() or "refresh" in response.text.lower()


class TestOptimisticLockConflict:
    """ConflictError raised during a route's save() must surface as 409."""

    def test_conflict_error_surfaces_as_409(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx)

        from seqsetup.repositories.base import ConflictError

        original_save = ctx.run_repo.save

        def raising_save(run):
            raise ConflictError(
                "Run was modified by another user since you loaded it. Refresh and retry."
            )

        ctx.run_repo.save = raising_save
        try:
            response = logged_in_client.post(
                f"/runs/{run_id}/name",
                data={"run_name": "Conflicting Edit"},
                headers=_origin(),
            )
        finally:
            ctx.run_repo.save = original_save

        assert response.status_code == 409
        assert "modified" in response.text.lower() or "refresh" in response.text.lower()
