"""Smoke tests for validation, approval, and status transitions.

These cover the clinically-sensitive paths:
- Approve refuses a run with errors (e.g., missing indexes).
- Transition to READY refuses without validation_approved.
- Transition to READY pre-generates exports.
- Optimistic locking surfaces as 409.
- ARCHIVED is terminal.
"""

import pytest

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
    """Set up a run that should be approvable: has samples, all have indexes.

    Samples have no test_id, and we null the profile repos on ctx AND on
    the startup module's repo cache — this forces validation to use the
    hardcoded BCLConvert path and skip the application-profile lookup that
    would otherwise fail with test_profile_not_found for un-seeded test
    types.
    """
    # Strip the profile repos so the application-profile validator and the
    # missing_test_id check both short-circuit. Tests that want to exercise
    # the profile-driven path should seed TestProfile + ApplicationProfile.
    ctx.test_profile_repo = None
    ctx.app_profile_repo = None
    # Also null the startup-level repo cache so that routes using
    # Depends(get_ctx) — which call get_app_context() each request — also
    # receive None for these repos.
    import seqsetup.startup as _startup
    _startup._repos["test_profile"] = None
    _startup._repos["app_profile"] = None

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


class TestApproval:
    def test_approve_succeeds_for_clean_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx)

        response = logged_in_client.post(
            f"/runs/{run_id}/validation/approve",
            headers=_origin(),
        )
        assert response.status_code == 200

        updated = ctx.run_repo.get_by_id(run_id)
        assert updated.validation_approved is True

    def test_approve_refuses_run_with_no_samples(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = SequencingRun(
            id="empty-run",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
        )
        ctx.run_repo.save(run)

        response = logged_in_client.post(
            f"/runs/empty-run/validation/approve",
            headers=_origin(),
        )
        # Route returns the bar component (200) but approval is NOT set.
        assert response.status_code == 200
        updated = ctx.run_repo.get_by_id("empty-run")
        assert updated.validation_approved is False

    def test_unapprove_clears_approval(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx)

        # Approve, then unapprove.
        logged_in_client.post(f"/runs/{run_id}/validation/approve", headers=_origin())
        response = logged_in_client.post(
            f"/runs/{run_id}/validation/unapprove",
            headers=_origin(),
        )
        assert response.status_code == 200
        assert ctx.run_repo.get_by_id(run_id).validation_approved is False


class TestStatusTransition:
    def test_transition_to_ready_refused_without_approval(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx)

        response = logged_in_client.post(
            f"/runs/{run_id}/status/ready",
            headers=_origin(),
        )
        # Route returns the bar (200) but status stays DRAFT.
        assert response.status_code == 200
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT

    def test_transition_to_ready_after_approval(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _make_ready_eligible_run(ctx)

        # Approve first, then transition.
        logged_in_client.post(f"/runs/{run_id}/validation/approve", headers=_origin())
        response = logged_in_client.post(
            f"/runs/{run_id}/status/ready",
            headers=_origin(),
        )
        assert response.status_code == 200

        updated = ctx.run_repo.get_by_id(run_id)
        assert updated.status == RunStatus.READY
        # Exports were pre-generated.
        assert updated.generated_samplesheet_v2 is not None
        assert "[BCLConvert_Data]" in updated.generated_samplesheet_v2
        assert updated.generated_json is not None

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
            f"/runs/archived-run/status/draft",
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

        # The route loads the run, captures _loaded_updated_at, then mutates
        # and calls run.save(). We simulate a concurrent edit by mutating
        # the stored updated_at *between* load and save. Achieved by
        # overriding `get_by_id` to mutate the stored doc after returning
        # the loaded copy.
        original_get = ctx.run_repo.get_by_id
        mutated = {"done": False}

        def get_then_mutate(rid):
            run = original_get(rid)
            if not mutated["done"] and run is not None and rid == run_id:
                # Mutate the stored doc so the load-time updated_at no
                # longer matches what's in MongoDB.
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
    """ConflictError raised during a route's save() must surface as 409.

    A natural concurrent-edit between two web requests is hard to simulate
    in a single TestClient — each handler loads its own copy of the run, so
    the load-time updated_at they capture matches the stored value. We
    inject the error directly at the repo layer to verify the exception
    handler wiring; the lock behaviour itself is covered by the repo's
    unit tests (test_run_repo_optimistic_locking.py).
    """

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
