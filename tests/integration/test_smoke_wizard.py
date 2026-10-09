"""Smoke tests for the run-creation wizard and run editing.

Covers the core HTMX flows that build up a run from blank to ready:
- GET /runs/new creates a draft and redirects to step 1
- POST /runs/{id}/name updates name (HTMX target)
- POST /runs/{id}/samples adds a sample (HTMX target)
- POST /runs/{id}/instrument switches platform
"""

import pytest


def _origin() -> dict:
    """Same-origin POST header for the CSRF middleware."""
    return {"Origin": "http://testserver"}


def _create_run(logged_in_client) -> str:
    """Create a fresh run via the wizard and return its id."""
    response = logged_in_client.post(
        "/runs/new",
        follow_redirects=False,
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 303, response.text[:300]
    location = response.headers["location"]
    # Format: /runs/new/step/1?run_id=<uuid>
    assert "run_id=" in location
    return location.split("run_id=", 1)[1].split("&", 1)[0]


class TestRunCreation:
    def test_wizard_new_creates_draft_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        before = len(ctx.run_repo.list_all())

        response = logged_in_client.post(
            "/runs/new",
            follow_redirects=False,
            headers={"Origin": "http://testserver"},
        )
        assert response.status_code == 303

        after = len(ctx.run_repo.list_all())
        assert after == before + 1
        # Newly created run is in DRAFT.
        new_run = ctx.run_repo.list_all()[-1]
        assert new_run.status.value == "draft"

    def test_wizard_step1_renders_for_existing_run(self, logged_in_client):
        run_id = _create_run(logged_in_client)
        response = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}")
        assert response.status_code == 200
        # Some piece of the wizard UI is present.
        body = response.text.lower()
        assert "run" in body and ("name" in body or "instrument" in body)

    def test_wizard_step1_unknown_run_redirects_to_dashboard(self, logged_in_client):
        response = logged_in_client.get(
            "/runs/new/step/1?run_id=nonexistent-id",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/"


class TestRunEditing:
    def test_update_run_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)

        response = logged_in_client.post(
            f"/runs/{run_id}/name",
            data={"run_name": "Smoke Test Run"},
            headers=_origin(),
        )
        assert response.status_code == 200

        updated = ctx.run_repo.get_by_id(run_id)
        assert updated.run_name == "Smoke Test Run"

    def test_update_instrument_changes_platform(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)

        response = logged_in_client.post(
            f"/runs/{run_id}/instrument",
            data={"instrument_platform": "MiSeq i100 Series"},
            headers=_origin(),
        )
        assert response.status_code == 200

        updated = ctx.run_repo.get_by_id(run_id)
        assert updated.instrument_platform.value == "MiSeq i100 Series"


class TestSampleAddition:
    def test_add_sample_to_draft_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)

        response = logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "S001", "test_id": "WGS", "test_version": "1"},
            headers=_origin(),
        )
        assert response.status_code == 200

        updated = ctx.run_repo.get_by_id(run_id)
        assert len(updated.samples) == 1
        assert updated.samples[0].sample_id == "S001"
        assert updated.samples[0].test_id == "WGS"

    def test_add_sample_rejects_blank_sample_id(self, logged_in_client):
        run_id = _create_run(logged_in_client)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "", "test_id": "WGS"},
            headers=_origin(),
        )
        assert response.status_code == 400
        assert "required" in response.text.lower()


class TestEditingRequiresDraftStatus:
    """Mutations on a non-DRAFT run are rejected by get_editable_run dep."""

    def test_cannot_add_sample_to_ready_run(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)

        # Manually flip to READY (bypassing approval gate for this test).
        run = ctx.run_repo.get_by_id(run_id)
        from seqsetup.models.sequencing_run import RunStatus
        run.status = RunStatus.READY
        ctx.run_repo.save(run)

        response = logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "S001"},
            headers=_origin(),
        )
        assert response.status_code == 403


class TestUpdateSamplePartialUpdate:
    """POST /runs/{run_id}/samples/{sample_id} is a partial-update endpoint.
    Per CLAUDE.md, a field NOT present in the form must NOT be silently
    blanked — the legacy behaviour would wipe sibling fields whenever a
    future per-field input was added to the row."""

    def _setup_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "S001", "sample_name": "Patient A", "project": "P-42"},
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.samples[0].sample_name == "Patient A"
        assert run.samples[0].project == "P-42"
        return ctx, run_id, run.samples[0].id

    def test_post_only_sample_id_preserves_name_and_project(
        self, logged_in_client, fresh_app
    ):
        ctx, run_id, sample_uuid = self._setup_sample(logged_in_client, fresh_app)
        # Submit a form that ONLY changes sample_id — sample_name/project
        # must remain. (Mirrors a future per-field input on just sample_id.)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_uuid}",
            data={"sample_id": "S002"},
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        s = next(s for s in run.samples if s.id == sample_uuid)
        assert s.sample_id == "S002"
        assert s.sample_name == "Patient A", "sample_name must be preserved"
        assert s.project == "P-42", "project must be preserved"

    def test_post_only_sample_name_preserves_sample_id_and_project(
        self, logged_in_client, fresh_app
    ):
        ctx, run_id, sample_uuid = self._setup_sample(logged_in_client, fresh_app)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_uuid}",
            data={"sample_name": "Patient B"},
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        s = next(s for s in run.samples if s.id == sample_uuid)
        assert s.sample_id == "S001", "sample_id must be preserved"
        assert s.sample_name == "Patient B"
        assert s.project == "P-42"

    def test_post_with_blank_sample_id_is_rejected(self, logged_in_client, fresh_app):
        ctx, run_id, sample_uuid = self._setup_sample(logged_in_client, fresh_app)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_uuid}",
            data={"sample_id": "   "},
            headers=_origin(),
        )
        assert response.status_code == 400
        run = ctx.run_repo.get_by_id(run_id)
        s = next(s for s in run.samples if s.id == sample_uuid)
        assert s.sample_id == "S001"  # untouched


class TestUpdateSampleSettingsPartialUpdate:
    """update_sample_settings is the per-field HTMX endpoint — a request
    that posts only override_cycles must not wipe the barcode mismatch
    siblings, and vice versa."""

    def _setup_with_index(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        # Add a sample with explicit index sequences so override_cycles can
        # be computed when blank is submitted.
        response = logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "S001"},
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        sample = run.samples[0]
        # Seed the row's pre-existing settings.
        sample.barcode_mismatches_index1 = 2
        sample.barcode_mismatches_index2 = 0
        sample.override_cycles = "Y151;I10;I10;Y151"
        ctx.run_repo.save(run)
        return ctx, run_id, sample.id

    def test_posting_only_override_cycles_preserves_mismatch_overrides(
        self, logged_in_client, fresh_app
    ):
        ctx, run_id, sample_uuid = self._setup_with_index(logged_in_client, fresh_app)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_uuid}/settings",
            data={"override_cycles": "Y151;I8N2;I8N2;Y151"},
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        s = next(s for s in run.samples if s.id == sample_uuid)
        assert s.override_cycles == "Y151;I8N2;I8N2;Y151"
        assert s.barcode_mismatches_index1 == 2, "bmi1 must be preserved"
        assert s.barcode_mismatches_index2 == 0, "bmi2 must be preserved"

    def test_posting_only_bmi1_preserves_other_settings(
        self, logged_in_client, fresh_app
    ):
        ctx, run_id, sample_uuid = self._setup_with_index(logged_in_client, fresh_app)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_uuid}/settings",
            data={"barcode_mismatches_index1": "1"},
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        s = next(s for s in run.samples if s.id == sample_uuid)
        assert s.barcode_mismatches_index1 == 1
        assert s.barcode_mismatches_index2 == 0, "bmi2 must be preserved"
        assert s.override_cycles == "Y151;I10;I10;Y151", "override_cycles must be preserved"


class TestBulkPasteSizeCap:
    """Authenticated users must not be able to blow past MongoDB's 16 MB
    BSON limit via a multi-MB paste_data body."""

    def test_paste_data_over_10mb_rejected(self, logged_in_client, fresh_app):
        run_id = _create_run(logged_in_client)
        too_big = "S1,T1,ACGT,ACGT\n" * (10 * 1024 * 1024 // 16 + 100)  # > 10 MB
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/bulk",
            data={"paste_data": too_big, "lanes": "1"},
            headers=_origin(),
        )
        assert response.status_code == 400
        assert "too large" in response.text.lower()

    def test_paste_data_with_invalid_row_rejects_whole_import(
        self, logged_in_client, fresh_app
    ):
        """Reject-the-whole-import semantics — a worklist with one bad row
        must not silently produce a partial run."""
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        # Row 2 has content but no sample_id.
        paste = "Sample_ID,Test_ID,Index_I7,Index_I5\nS1,WGS,ATTACTCG,TATAGCCT\n,WGS,ATTACTCG,TATAGCCT\n"
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/bulk",
            data={"paste_data": paste, "lanes": "1"},
            headers=_origin(),
        )
        # The handler renders the sample section with an error banner; the
        # status is 200 because HTMX needs the swap. The body must contain
        # the rejection text and the run must have NO samples added.
        assert response.status_code == 200
        assert "rejected" in response.text.lower()
        run = ctx.run_repo.get_by_id(run_id)
        assert len(run.samples) == 0


class TestReadyToDraftClearsExports:
    """READY → DRAFT puts the run back into the editable pool; pre-generated
    exports must be dropped so a re-promotion never adopts pre-edit blobs.
    READY → ARCHIVED retains them — archived runs serve those bytes."""

    def test_ready_to_draft_clears_pregenerated_exports(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        run = ctx.run_repo.get_by_id(run_id)
        from seqsetup.models.sequencing_run import RunStatus
        run.status = RunStatus.READY
        run.generated_samplesheet_v2 = "stale-sheet"
        run.generated_samplesheet_v1 = "stale-v1"
        run.generated_json = "stale-json"
        run.generated_validation_json = "stale-val"
        run.generated_validation_pdf = b"stale-pdf"
        ctx.run_repo.save(run)

        response = logged_in_client.post(
            f"/runs/{run_id}/status/draft",
            headers=_origin(),
        )
        assert response.status_code == 200

        refreshed = ctx.run_repo.get_by_id(run_id)
        assert refreshed.status == RunStatus.DRAFT
        assert refreshed.generated_samplesheet_v2 is None
        assert refreshed.generated_samplesheet_v1 is None
        assert refreshed.generated_json is None
        assert refreshed.generated_validation_json is None
        assert refreshed.generated_validation_pdf is None

    def test_ready_to_archived_retains_pregenerated_exports(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        run = ctx.run_repo.get_by_id(run_id)
        from seqsetup.models.sequencing_run import RunStatus
        run.status = RunStatus.READY
        run.generated_samplesheet_v2 = "snapshot-sheet"
        run.generated_json = "snapshot-json"
        ctx.run_repo.save(run)

        response = logged_in_client.post(
            f"/runs/{run_id}/status/archived",
            headers=_origin(),
        )
        assert response.status_code == 200

        refreshed = ctx.run_repo.get_by_id(run_id)
        assert refreshed.status == RunStatus.ARCHIVED
        assert refreshed.generated_samplesheet_v2 == "snapshot-sheet"
        assert refreshed.generated_json == "snapshot-json"


class TestBulkHandlersReachRoutes:
    """Smoke coverage for the previously-untested bulk mutation handlers.
    Each test exercises the wire format (HTMX form post) and verifies the
    mutation lands on the model and emits the appropriate audit event
    indirectly via the changed run state."""

    def _setup_two_samples(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "S1"},
            headers=_origin(),
        )
        logged_in_client.post(
            f"/runs/{run_id}/samples",
            data={"sample_id": "S2"},
            headers=_origin(),
        )
        run = ctx.run_repo.get_by_id(run_id)
        return ctx, run_id, [s.id for s in run.samples]

    def test_set_test_id_bulk(self, logged_in_client, fresh_app):
        ctx, run_id, ids = self._setup_two_samples(logged_in_client, fresh_app)
        import json
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/set-test-id",
            data={"sample_ids": json.dumps(ids), "test_id": "WGS", "test_version": "1"},
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert all(s.test_id == "WGS" for s in run.samples)

    def test_set_mismatches_bulk(self, logged_in_client, fresh_app):
        ctx, run_id, ids = self._setup_two_samples(logged_in_client, fresh_app)
        import json
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/set-mismatches",
            data={
                "sample_ids": json.dumps(ids),
                "mismatch_index1": "0",
                "mismatch_index2": "2",
            },
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        for s in run.samples:
            assert s.barcode_mismatches_index1 == 0
            assert s.barcode_mismatches_index2 == 2

    def test_delete_samples_bulk(self, logged_in_client, fresh_app):
        ctx, run_id, ids = self._setup_two_samples(logged_in_client, fresh_app)
        import json
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/bulk-delete",
            data={"sample_ids": json.dumps([ids[0]])},
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert len(run.samples) == 1
        assert run.samples[0].id == ids[1]

    def test_set_lanes_bulk(self, logged_in_client, fresh_app):
        ctx, run_id, ids = self._setup_two_samples(logged_in_client, fresh_app)
        # Pick a flowcell with multiple lanes — the default add_sample uses
        # lanes=[1], so setting to [1, 2] verifies the bulk handler ran.
        logged_in_client.post(
            f"/runs/{run_id}/flowcell",
            data={"flowcell_type": "25B"},
            headers=_origin(),
        )
        import json
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/set-lanes",
            data={"sample_ids": json.dumps(ids), "lanes": json.dumps([1, 2])},
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert all(s.lanes == [1, 2] for s in run.samples)

    def test_set_override_cycles_bulk(self, logged_in_client, fresh_app):
        ctx, run_id, ids = self._setup_two_samples(logged_in_client, fresh_app)
        import json
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/set-override-cycles",
            data={
                "sample_ids": json.dumps(ids),
                "override_cycles": "Y151;I8N2;I8N2;Y151",
            },
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        for s in run.samples:
            assert s.override_cycles == "Y151;I8N2;I8N2;Y151"

    def test_set_override_cycles_bulk_expands_wildcard(self, logged_in_client, fresh_app):
        """A '*' wildcard entered in the bulk override field is internal
        shorthand; it must be expanded to concrete cycle counts against the
        run's declared cycles before storage. '*' is not valid BCL Convert
        OverrideCycles, and the model rejects it — so without expansion this
        POST would 400 instead of storing an expanded value."""
        ctx, run_id, ids = self._setup_two_samples(logged_in_client, fresh_app)
        import json
        rc = ctx.run_repo.get_by_id(run_id).run_cycles
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/set-override-cycles",
            data={
                "sample_ids": json.dumps(ids),
                "override_cycles": "Y*;I8N2;I8N2;Y*",
            },
            headers=_origin(),
        )
        assert response.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        for s in run.samples:
            assert "*" not in s.override_cycles
            assert s.override_cycles == f"Y{rc.read1_cycles};I8N2;I8N2;Y{rc.read2_cycles}"

    def test_bulk_invalid_json_returns_named_400(self, logged_in_client, fresh_app):
        ctx, run_id, _ = self._setup_two_samples(logged_in_client, fresh_app)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/set-test-id",
            data={"sample_ids": "this is not json", "test_id": "WGS"},
            headers=_origin(),
        )
        assert response.status_code == 400
        # Must NAME the offending field — "Invalid request data" without
        # context made 2am clinical support calls undiagnosable.
        assert "sample_ids" in response.text.lower()
