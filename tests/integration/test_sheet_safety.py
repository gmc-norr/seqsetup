"""Sample Sheet safety through the real routes (audit 2026-09 N-10, N-11,
N-12, N-16)."""

from seqsetup.data import instruments as instruments_module
from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.instrument_definition import InstrumentDefinition, OnboardApplication
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
from seqsetup.services.validation import ValidationService, clear_validation_cache

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}


def _seed_draft(ctx, run_id: str, test_id: str = "", run_description: str = "Plan B") -> str:
    """A NovaSeq X DRAFT run with one indexed sample, ready to be marked ready."""
    run = SequencingRun(
        id=run_id,
        run_name="Safety",
        run_description=run_description,
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(Sample(
        sample_id="S1",
        test_id=test_id,
        index_pair=IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
    ))
    ctx.run_repo.save(run)
    return run.id


class TestMarkReadyRefusesHiddenCharacters:
    """A hidden character in run or sample text keeps the run in DRAFT."""

    def test_tab_in_run_description_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "hc-desc")
        assert logged_in_client.post(
            f"/runs/{run_id}/name",
            data={"run_name": "Safety", "run_description": "Plan\tB"},
            headers=ORIGIN,
        ).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#error-banner"
        assert "hidden character" in resp.text
        assert "U+0009" in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.status.value == "draft"
        assert not run.generated_samplesheet_v2

    def test_nul_in_sample_project_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "hc-project")
        sample_id = ctx.run_repo.get_by_id(run_id).samples[0].id
        assert logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_id}",
            data={"project": "P\x00Q"},
            headers=ORIGIN,
        ).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#error-banner"
        assert "U+0000" in resp.text
        assert ctx.run_repo.get_by_id(run_id).status.value == "draft"

    def test_visible_text_is_made_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_draft(ctx, "hc-control", run_description="Åsa's run, 2 × 150")

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert "HX-Retarget" not in resp.headers, resp.text[:400]
        assert ctx.run_repo.get_by_id(run_id).status.value == "ready"


def _seed_synced_profile(ctx, app_name: str) -> None:
    """What a config sync stores, written straight to the database so the
    sync validator is bypassed. The synced instrument lists the same
    application, so the existing app_not_available check passes and Mark
    Ready reaches the Sample Sheet writer."""
    ctx.app_profile_repo.save(ApplicationProfile(
        name="GuardProfile",
        version="1.0",
        application_type="Dragen",
        application_name=app_name,
        settings={"SoftwareVersion": "4.3.6"},
        data={},
        data_fields=["Sample_ID", "Index", "Index2"],
        translate={},
    ))
    ctx.test_profile_repo.save(TestProfile(
        test_type="GUARD_T",
        test_name="Guard",
        description="d",
        version="1.0",
        application_profiles=[
            ApplicationProfileReference(profile_name="GuardProfile", profile_version="1.0")
        ],
    ))
    ctx.instrument_definition_repo.save(InstrumentDefinition(
        name="NovaSeq X Series",
        samplesheet_name="NovaSeqXSeries",
        version="1.0.0",
        chemistry_type="2-color",
        onboard_applications=[OnboardApplication(name=app_name, software_version="4.3.6")],
    ))
    instruments_module.clear_synced_instruments_cache()
    clear_validation_cache()


def _assert_validation_passes(ctx, run_id: str) -> None:
    run = ctx.run_repo.get_by_id(run_id)
    result = ValidationService.validate_run(
        run,
        test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config,
    )
    assert result.error_count == 0, "validation must pass, so only the export guard can stop Mark Ready"


class TestExportGuardStopsBadSyncedNames:
    """A synced ApplicationName that slipped past the sync check stops Mark
    Ready at the Sample Sheet writer; the run stays Draft (audit 2026-09 N-10)."""

    def test_bad_application_name_stops_mark_ready(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        try:
            _seed_synced_profile(ctx, "Evil\n[Junk")
            run_id = _seed_draft(ctx, "guard-appname", test_id="GUARD_T")
            _assert_validation_passes(ctx, run_id)

            resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

            assert resp.status_code == 500
            assert "Failed to generate exports" in resp.text
            run = ctx.run_repo.get_by_id(run_id)
            assert run.status.value == "draft"
            assert run.generated_samplesheet_v2 is None
        finally:
            instruments_module.clear_synced_instruments_cache()
            clear_validation_cache()

    def test_plain_application_name_is_made_ready(self, logged_in_client, fresh_app):
        """CONTROL: the same setup with a plain name is marked ready, so the
        test above fails only because of the name."""
        _app, ctx, _db = fresh_app
        try:
            _seed_synced_profile(ctx, "GuardApp")
            run_id = _seed_draft(ctx, "guard-control", test_id="GUARD_T")
            _assert_validation_passes(ctx, run_id)

            resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

            assert resp.status_code == 200, resp.text[:400]
            assert "HX-Retarget" not in resp.headers, resp.text[:400]
            run = ctx.run_repo.get_by_id(run_id)
            assert run.status.value == "ready"
            assert "[GuardApp_Settings]" in run.generated_samplesheet_v2
        finally:
            instruments_module.clear_synced_instruments_cache()
            clear_validation_cache()


class TestRunNameRouteKeepsUnsentFields:
    """POST /runs/{id}/name writes only the fields it was sent (audit 2026-09
    N-16; CLAUDE.md "Partial updates update only what was submitted")."""

    def test_name_only_keeps_the_description(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed_draft(ctx, "n16-name", run_description="KEEP-THIS-DESCRIPTION")

        resp = logged_in_client.post(
            f"/runs/{run_id}/name", data={"run_name": "Renamed"}, headers=ORIGIN
        )

        assert resp.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.run_name == "Renamed"
        assert run.run_description == "KEEP-THIS-DESCRIPTION"

    def test_description_only_keeps_the_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed_draft(ctx, "n16-desc")

        resp = logged_in_client.post(
            f"/runs/{run_id}/name", data={"run_description": "New plan"}, headers=ORIGIN
        )

        assert resp.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.run_name == "Safety"
        assert run.run_description == "New plan"

    def test_both_fields_are_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed_draft(ctx, "n16-both")

        resp = logged_in_client.post(
            f"/runs/{run_id}/name",
            data={"run_name": "Both", "run_description": ""},
            headers=ORIGIN,
        )

        assert resp.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        assert run.run_name == "Both"
        assert run.run_description == ""

    def test_neither_field_is_refused_and_nothing_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed_draft(ctx, "n16-none")
        before = ctx.run_repo.get_by_id(run_id).updated_at

        resp = logged_in_client.post(f"/runs/{run_id}/name", data={}, headers=ORIGIN)

        assert resp.status_code == 400
        assert "Nothing to save" in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.updated_at == before
        assert (run.run_name, run.run_description) == ("Safety", "Plan B")
