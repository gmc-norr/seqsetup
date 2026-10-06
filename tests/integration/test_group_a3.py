"""Group A3 through the real routes (spec 2026-10-05): the Sample Sheet carries
what Mark Ready checked."""

import html

import pytest

from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


ORIGIN = {"Origin": "http://testserver"}
NOVASEQ_X = InstrumentPlatform.NOVASEQ_X

INDEX1_ORDER_RULE = (
    "Index 1 in OverrideCycles starts with the index in SeqSetup: the index first, then any "
    "masked or UMI cycles (for example I8N2 or I8U9). SeqSetup's checks compare the index "
    "from the first cycle of its read."
)
INDEX_SPLIT_RULE = (
    "An index part of OverrideCycles holds one run of index cycles in SeqSetup (for example "
    "I8N2, not I4N2I4). SeqSetup's checks compare the index as one run of cycles."
)
INDEX2_ORDER_RULE = (
    "Index 2 in OverrideCycles is written in reading order in SeqSetup: the index first, then "
    "the masked cycles (for example I8N2). SeqSetup writes it the way the instrument needs."
)


def _indexed_draft(ctx, run_id: str, override: str = "", i7: str = "ATTACTCG",
                   i5: str = "TATAGCCT", cycles: RunCycles = RunCycles(151, 151, 10, 10),
                   index1_cycles=None, test_id: str = "") -> SequencingRun:
    from seqsetup.models.index import Index, IndexPair, IndexType
    from seqsetup.models.sample import Sample
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=NOVASEQ_X,
                        flowcell_type="10B", run_cycles=cycles)
    run.add_sample(Sample(sample_id="S1", lanes=[1], override_cycles=override or None,
                          index1_cycles=index1_cycles, test_id=test_id,
                          index_pair=IndexPair(
                              id="p1", name="p1",
                              index1=Index(name="i7", sequence=i7, index_type=IndexType.I7),
                              index2=Index(name="i5", sequence=i5, index_type=IndexType.I5),
                          )))
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


REFUSED = [
    pytest.param("Y151;N2I8;I8N2;Y151", INDEX1_ORDER_RULE, id="index-1-masked-first"),
    pytest.param("Y151;Y2I8;I8N2;Y151", INDEX1_ORDER_RULE, id="index-1-y-first"),
    pytest.param("Y151;I8N2;Y2I8;Y151", INDEX2_ORDER_RULE, id="index-2-y-first"),
    pytest.param("Y151;I4N2I4;I8N2;Y151", INDEX_SPLIT_RULE, id="index-1-split"),
    pytest.param("Y151;I8N2;I4N2I4;Y151", INDEX_SPLIT_RULE, id="index-2-split"),
]


class TestATypedIndexPartIsRefused:
    """An index part that does not start with the index, or holds two runs of
    index cycles, is refused where it is typed and at Mark Ready (spec §4)."""

    @pytest.mark.parametrize("value,rule", REFUSED)
    def test_the_sample_input_refuses_it(self, logged_in_client, fresh_app, value, rule):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a3-typed-row")
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"override_cycles": value}, headers=ORIGIN,
        )
        assert resp.status_code == 400
        assert f"{rule} Nothing was saved." in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).samples[0].override_cycles is None

    @pytest.mark.parametrize("value,rule", REFUSED)
    def test_the_bulk_input_refuses_it(self, logged_in_client, fresh_app, value, rule):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a3-typed-bulk")
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-override-cycles",
            data={"sample_ids": f'["{run.samples[0].id}"]', "override_cycles": value},
            headers=ORIGIN,
        )
        assert resp.status_code == 400
        assert f"{rule} Nothing was saved." in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).samples[0].override_cycles is None

    @pytest.mark.parametrize("value", ["Y151;I8N2;I8N2;Y151", "Y151;I8U2;N10;Y151"])
    def test_the_index_first_is_saved(self, logged_in_client, fresh_app, value):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a3-typed-ok")
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"override_cycles": value}, headers=ORIGIN,
        )
        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run.id).samples[0].override_cycles == value

    @pytest.mark.parametrize("value,rule", REFUSED)
    def test_mark_ready_refuses_a_stored_one(self, logged_in_client, fresh_app, value, rule):
        from .conftest import disable_repos
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = _indexed_draft(ctx, "a3-typed-ready", override=value)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert rule in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT


class TestAnIndexMustBeAsLongAsTheCyclesRead:
    """Mark Ready refuses an index whose length differs from the cycles its
    OverrideCycles reads for it (spec §4)."""

    def test_kit_cycles_shorter_than_the_index_on_an_equal_read(self, logged_in_client, fresh_app):
        # A 10-base i7 with kit index cycles 8 on an 8-cycle read: 0 errors before.
        from .conftest import disable_repos
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = _indexed_draft(ctx, "a3-length", i7="ATTACTCGAT", cycles=RunCycles(151, 151, 8, 8),
                             index1_cycles=8)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert (
            "1 sample(s) have an index whose length differs from the index cycles their "
            "OverrideCycles reads: S1 (i7: 10 bases, 8 read)."
        ) in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT



class TestTheClearText:
    """Clear on the mismatch numbers resets them to the default, which on the
    profile path is the BCL Convert profile's (spec §2)."""

    def test_an_empty_apply_says_what_clear_resets_to(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "a3-clear")
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-mismatches",
            data={"sample_ids": f'["{run.samples[0].id}"]', "mismatch_index1": "",
                  "mismatch_index2": ""},
            headers=ORIGIN,
        )
        assert resp.status_code == 400
        assert (
            "Type a barcode mismatch value (0, 1 or 2) to apply, or use Clear to reset both to "
            "the default (the BCL Convert profile's, else the run's). Nothing was saved."
        ) in html.unescape(resp.text)


PROFILES_CHANGED = (
    "The profiles changed while the exports were being generated, so the Sample Sheet would "
    "not match what was checked. The run is still a Draft. Mark it Ready again."
)
BCL_FIELDS = ["Sample_ID", "Lane", "Index", "Index2", "OverrideCycles",
              "BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"]


def _bcl_profile(mismatch_default=1, profile_id=None):
    from seqsetup.models.application_profile import ApplicationProfile
    fields = dict(
        name="A3BCL", version="1.0.0", application_type="Dragen", application_name="BCLConvert",
        settings={"SoftwareVersion": "4.3.6"},
        data={"BarcodeMismatchesIndex1": mismatch_default, "BarcodeMismatchesIndex2": 1},
        data_fields=list(BCL_FIELDS), translate={},
    )
    return ApplicationProfile(id=profile_id, **fields) if profile_id else ApplicationProfile(**fields)


@pytest.fixture
def profiles(fresh_app):
    """A BCLConvert profile, a test A3T that lists it, and a synced NovaSeq X
    that offers BCLConvert 4.3.6, so a run on A3T passes the checks."""
    from seqsetup.data import instruments as instruments_module
    from seqsetup.models.instrument_definition import InstrumentDefinition, OnboardApplication
    from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
    from seqsetup.services.validation import clear_validation_cache
    _app, ctx, _db = fresh_app
    ctx.app_profile_repo.save(_bcl_profile())
    ctx.test_profile_repo.save(TestProfile(
        test_type="A3T", test_name="A3T", description="d", version="1.0.0",
        application_profiles=[ApplicationProfileReference(profile_name="A3BCL",
                                                          profile_version="1.0.0")]))
    ctx.instrument_definition_repo.save(InstrumentDefinition(
        name="NovaSeq X Series", samplesheet_name="NovaSeqXSeries", version="1.0.0",
        chemistry_type="2-color",
        onboard_applications=[OnboardApplication(name="BCLConvert", software_version="4.3.6")],
        i5_workflows=[{"name": "Standard", "i5_read_orientation": "reverse-complement"}],
        runinfo_marks_i5_reversed=True,
    ))
    instruments_module.clear_synced_instruments_cache()
    clear_validation_cache()
    yield ctx
    instruments_module.clear_synced_instruments_cache()
    clear_validation_cache()


def _during_the_writing(monkeypatch, change):
    """Run ``change`` the moment the v2 writer starts at Mark Ready."""
    from seqsetup.routes import runs as runs_module
    original = runs_module.SampleSheetV2Exporter.export

    def export(run, *args, **kw):
        change()
        return original(run, *args, **kw)

    monkeypatch.setattr(runs_module.SampleSheetV2Exporter, "export", export)


def _denial_reasons(ctx) -> list[str]:
    return [e.details["reason"]
            for e in ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied")]


class TestTheWriterWritesFromThePlanTheChecksPassed:
    """A profile that changes between Mark Ready's checks and the writing
    makes Mark Ready refuse; the run stays a Draft (spec §1)."""

    def _refused(self, client, ctx, run_id):
        from .conftest import mark_ready
        resp = mark_ready(client, run_id, ORIGIN)
        assert resp.status_code == 409
        assert PROFILES_CHANGED in html.unescape(resp.text)
        run = ctx.run_repo.get_by_id(run_id)
        assert run.status == RunStatus.DRAFT
        assert run.generated_samplesheet_v2 is None
        assert "profiles_changed_during_export" in _denial_reasons(ctx)

    def test_a_deleted_profile(self, logged_in_client, profiles, monkeypatch):
        # The DI-07 timing: the sync's delete_all lands before the writer.
        run = _indexed_draft(profiles, "a3-deleted", test_id="A3T")
        _during_the_writing(monkeypatch, profiles.test_profile_repo.delete_all)
        self._refused(logged_in_client, profiles, run.id)

    def test_a_data_default_1_to_2(self, logged_in_client, profiles, monkeypatch):
        run = _indexed_draft(profiles, "a3-default", test_id="A3T")
        stored = profiles.app_profile_repo.list_all()[0]
        _during_the_writing(monkeypatch, lambda: profiles.app_profile_repo.save(
            _bcl_profile(mismatch_default=2, profile_id=stored.id)))
        self._refused(logged_in_client, profiles, run.id)

    def test_a_cached_check_from_before_the_sync(self, logged_in_client, profiles):
        from seqsetup.services.validation import ValidationService
        run = _indexed_draft(profiles, "a3-cached", test_id="A3T")
        ValidationService.validate_run(
            run, test_profile_repo=profiles.test_profile_repo,
            app_profile_repo=profiles.app_profile_repo,
            instrument_config=profiles.instrument_config)
        stored = profiles.app_profile_repo.list_all()[0]
        profiles.app_profile_repo.save(_bcl_profile(mismatch_default=2, profile_id=stored.id))
        self._refused(logged_in_client, profiles, run.id)

    def test_after_the_409_the_next_mark_ready_checks_again(self, logged_in_client, profiles):
        # A sync that stored a profile but stopped before it cleared the
        # validation cache: the 409 clears it, so "Mark it Ready again" works
        # (spec §1, The plan's fingerprint).
        from seqsetup.services.validation import ValidationService
        from .conftest import mark_ready
        run = _indexed_draft(profiles, "a3-again", test_id="A3T")
        ValidationService.validate_run(
            run, test_profile_repo=profiles.test_profile_repo,
            app_profile_repo=profiles.app_profile_repo,
            instrument_config=profiles.instrument_config)
        stored = profiles.app_profile_repo.list_all()[0]
        profiles.app_profile_repo.save(_bcl_profile(mismatch_default=2, profile_id=stored.id))
        self._refused(logged_in_client, profiles, run.id)
        mark_ready(logged_in_client, run.id, ORIGIN)
        assert profiles.run_repo.get_by_id(run.id).status == RunStatus.READY

    def test_a_sync_that_only_renews_ids_is_not_a_change(self, logged_in_client, profiles,
                                                          monkeypatch):
        from .conftest import mark_ready

        def resync():
            profiles.app_profile_repo.delete_all()
            profiles.app_profile_repo.save(_bcl_profile())   # a new id and synced_at
        run = _indexed_draft(profiles, "a3-renewed", test_id="A3T")
        _during_the_writing(monkeypatch, resync)
        mark_ready(logged_in_client, run.id, ORIGIN)
        assert profiles.run_repo.get_by_id(run.id).status == RunStatus.READY

    def test_no_change_no_refusal(self, logged_in_client, profiles):
        from .conftest import mark_ready
        run = _indexed_draft(profiles, "a3-unchanged", test_id="A3T")
        mark_ready(logged_in_client, run.id, ORIGIN)
        assert profiles.run_repo.get_by_id(run.id).status == RunStatus.READY

    def test_a_report_from_another_plan(self, logged_in_client, profiles, monkeypatch):
        # The validation report made with the sheet must come from the plan
        # the checks passed too (spec §1, The plan's fingerprint).
        from dataclasses import replace
        from seqsetup.routes import runs as runs_module
        run = _indexed_draft(profiles, "a3-report", test_id="A3T")
        written = []
        export = runs_module.SampleSheetV2Exporter.export
        validate = runs_module.ValidationService.validate_run

        def export_then_note(run_, *args, **kw):
            sheet = export(run_, *args, **kw)
            written.append(True)
            return sheet

        def validate_another_plan_after_the_writing(*args, **kw):
            result = validate(*args, **kw)
            return replace(result, sheet_plan_fingerprint="another") if written else result

        monkeypatch.setattr(runs_module.SampleSheetV2Exporter, "export", export_then_note)
        monkeypatch.setattr(runs_module.ValidationService, "validate_run",
                            validate_another_plan_after_the_writing)
        self._refused(logged_in_client, profiles, run.id)

    def test_a_plan_problem_at_the_writer_is_audited(self, logged_in_client, profiles, monkeypatch):
        from seqsetup.routes import runs as runs_module
        from seqsetup.services.sheet_plan import SheetPlanProblem
        from .conftest import mark_ready
        run = _indexed_draft(profiles, "a3-problem", test_id="A3T")

        def stop(*_args, **_kw):
            raise SheetPlanProblem("Test 'A3T' has no test profile.")

        monkeypatch.setattr(runs_module.SampleSheetV2Exporter, "export", stop)
        resp = mark_ready(logged_in_client, run.id, ORIGIN)
        assert resp.status_code == 500
        assert "Failed to generate exports" in resp.text
        assert profiles.run_repo.get_by_id(run.id).status == RunStatus.DRAFT
        assert "sheet_plan_problem" in _denial_reasons(profiles)
