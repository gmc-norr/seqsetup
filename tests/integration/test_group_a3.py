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
                   index1_cycles=None, test_id: str = "",
                   test_version: str = "1") -> SequencingRun:
    from seqsetup.models.index import Index, IndexPair, IndexType
    from seqsetup.models.sample import Sample
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=NOVASEQ_X,
                        flowcell_type="10B", run_cycles=cycles)
    run.add_sample(Sample(sample_id="S1", lanes=[1], override_cycles=override or None,
                          index1_cycles=index1_cycles, test_id=test_id,
                          test_version=test_version if test_id else "",
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



class TestTheSyncRefusesNamesTheSheetWouldNotCarry:
    """A profile file with a repeated column, a BCLConvert setting also
    written as a column, or another spelling of a name SeqSetup fills is
    skipped and logged; the others sync (spec §1)."""

    @pytest.mark.parametrize("change,logged", [
        pytest.param(("  - Index2\n", "  - Index2\n  - index\n"),
                     "The data section writes the column 'Index' more than once", id="repeated"),
        pytest.param(("Settings:\n", "Settings:\n  Index: x\n"),
                     "'Index' is both in Settings and a data column", id="two-places"),
        pytest.param(("  SoftwareVersion:", "  softwareversion:"),
                     "'softwareversion' must be spelled SoftwareVersion", id="spelling"),
    ])
    def test_the_file_is_skipped_and_logged(self, fresh_app, monkeypatch, change, logged):
        from .test_sheet_followups import _SYNC_LOGGER, _Messages, _app_profile_yaml, _sync
        _app, ctx, _db = fresh_app
        bad = _app_profile_yaml("Bad", '"4.3.6"').replace(*change)
        assert bad != _app_profile_yaml("Bad", '"4.3.6"')
        handler = _Messages()
        _SYNC_LOGGER.addHandler(handler)
        try:
            ok, message, _count = _sync(ctx, monkeypatch, {
                "Good.yaml": _app_profile_yaml("Good", '"4.3.6"'), "Bad.yaml": bad,
            })
        finally:
            _SYNC_LOGGER.removeHandler(handler)

        assert ok, message
        assert [p.name for p in ctx.app_profile_repo.list_all()] == ["Good"]
        assert any("Bad.yaml" in m and logged in m for m in handler.messages), handler.messages



V1_REASON = (
    "S1 were checked with mismatch numbers other than the run's (i7 1, i5 1), which a v1 "
    "sheet writes"
)


def _miseq_draft(ctx, run_id: str, mismatch_index1=1, status=RunStatus.DRAFT, **fields):
    from seqsetup.models.index import Index, IndexPair, IndexType
    from seqsetup.models.sample import Sample
    from .conftest import disable_repos
    disable_repos(ctx, "test_profile", "app_profile")
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=InstrumentPlatform.MISEQ,
                        flowcell_type="v3", run_cycles=RunCycles(151, 151, 8, 8), status=status,
                        **fields)
    run.add_sample(Sample(sample_id="S1", lanes=[1], barcode_mismatches_index1=mismatch_index1,
                          index_pair=IndexPair(
                              id="p1", name="p1",
                              index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                              index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
                          )))
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


def _api_get(client, ctx, path: str):
    from seqsetup.models.api_token import ApiToken
    plaintext = ApiToken.generate_token()
    token_hash, token_prefix = ApiToken.hash_token(plaintext)
    ctx.api_token_repo.save(ApiToken(name="a3", token_hash=token_hash, token_prefix=token_prefix))
    return client.get(path, headers={"Authorization": f"Bearer {plaintext}"})


class TestNoV1SheetWhenItCannotCarryTheSettings:
    """Mark Ready works and makes the v2 sheet; no v1 sheet is stored, and the
    reason is, where the v1 sheet would be (spec §3)."""

    def _ready(self, client, ctx, run_id, **fields):
        from .conftest import mark_ready
        run = _miseq_draft(ctx, run_id, **fields)
        mark_ready(client, run.id, ORIGIN)
        return ctx.run_repo.get_by_id(run.id)

    def test_mark_ready_stores_the_reason_and_no_v1_sheet(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = self._ready(logged_in_client, ctx, "a3-v1", mismatch_index1=0)
        assert run.status == RunStatus.READY
        assert run.generated_samplesheet_v2
        assert run.generated_samplesheet_v1 is None
        assert run.samplesheet_v1_withheld == V1_REASON

    def test_a_plain_run_still_gets_its_v1_sheet(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = self._ready(logged_in_client, ctx, "a3-v1-plain")
        assert run.generated_samplesheet_v1 and run.samplesheet_v1_withheld == ""

    def test_the_export_panel_says_why(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = self._ready(logged_in_client, ctx, "a3-v1-panel", mismatch_index1=0)
        page = html.unescape(logged_in_client.get(f"/runs/{run.id}").text)
        assert f"No v1 sheet for this run: {V1_REASON}." in page
        assert f"/runs/{run.id}/export/samplesheet-v1" not in page

    def test_the_download_answers_409(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = self._ready(logged_in_client, ctx, "a3-v1-download", mismatch_index1=0)
        resp = logged_in_client.get(f"/runs/{run.id}/export/samplesheet-v1")
        assert resp.status_code == 409
        assert resp.text == f"No v1 sheet for this run: {V1_REASON}."

    def test_the_api_says_why(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = self._ready(logged_in_client, ctx, "a3-v1-api", mismatch_index1=0)
        resp = _api_get(logged_in_client, ctx, f"/api/runs/{run.id}/samplesheet-v1")
        assert resp.status_code == 404
        assert resp.json()["detail"] == f"No v1 sheet for this run: {V1_REASON}."

    def test_back_to_draft_clears_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = self._ready(logged_in_client, ctx, "a3-v1-draft", mismatch_index1=0)
        logged_in_client.post(f"/runs/{run.id}/status/draft", headers=ORIGIN)
        run = ctx.run_repo.get_by_id(run.id)
        assert run.status == RunStatus.DRAFT and run.samplesheet_v1_withheld == ""

    def test_the_stored_reason_is_shown_whatever_is_true_now(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _miseq_draft(ctx, "a3-v1-stored", status=RunStatus.READY,
                           generated_samplesheet_v2="[Header]\n", samplesheet_v1_withheld="X")
        resp = logged_in_client.get(f"/runs/{run.id}/export/samplesheet-v1")
        assert resp.status_code == 409 and resp.text == "No v1 sheet for this run: X."

    def test_a_run_from_before_stored_exports_gets_a_sheet_only_without_a_reason(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        plain = _miseq_draft(ctx, "a3-v1-old", status=RunStatus.READY)
        resp = logged_in_client.get(f"/runs/{plain.id}/export/samplesheet-v1")
        assert resp.status_code == 200 and "[Data]" in resp.text
        own = _miseq_draft(ctx, "a3-v1-old-own", mismatch_index1=0, status=RunStatus.READY)
        resp = logged_in_client.get(f"/runs/{own.id}/export/samplesheet-v1")
        assert resp.status_code == 409 and resp.text == f"No v1 sheet for this run: {V1_REASON}."

    def test_it_is_left_out_of_the_fingerprint_and_the_change_history(self):
        from seqsetup.routes.runs import _FINGERPRINT_IGNORED_KEYS
        from seqsetup.services.run_diff import RUN_DIFF_IGNORED_KEYS
        assert "samplesheet_v1_withheld" in _FINGERPRINT_IGNORED_KEYS
        assert "samplesheet_v1_withheld" in RUN_DIFF_IGNORED_KEYS


@pytest.fixture
def miseq_profiles(fresh_app):
    """A synced MiSeq that offers BCLConvert 4.3.6, the BCLConvert profile with
    a Data default of 0 for BarcodeMismatchesIndex1, and a test A3M that lists
    it: the checks use 0 for a cleared sample, the run's number is 1."""
    from seqsetup.data import instruments as instruments_module
    from seqsetup.models.instrument_definition import InstrumentDefinition, OnboardApplication
    from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
    from seqsetup.services.validation import clear_validation_cache
    _app, ctx, _db = fresh_app
    ctx.app_profile_repo.save(_bcl_profile(mismatch_default=0))
    ctx.test_profile_repo.save(TestProfile(
        test_type="A3M", test_name="A3M", description="d", version="1.0.0",
        application_profiles=[ApplicationProfileReference(profile_name="A3BCL",
                                                          profile_version="1.0.0")]))
    ctx.instrument_definition_repo.save(InstrumentDefinition(
        name="MiSeq", samplesheet_name="MiSeq", version="1.0.0", chemistry_type="4-color",
        onboard_applications=[OnboardApplication(name="BCLConvert", software_version="4.3.6")],
        i5_workflows=[{"name": "Standard", "i5_read_orientation": "forward"}],
        runinfo_marks_i5_reversed=False,
    ))
    instruments_module.clear_synced_instruments_cache()
    clear_validation_cache()
    yield ctx
    instruments_module.clear_synced_instruments_cache()
    clear_validation_cache()


def _miseq_profile_draft(ctx, run_id: str, index_cycles=8, i7="ATTACTCG", i5="TATAGCCT",
                         mismatch_index1=None):
    from seqsetup.models.index import Index, IndexPair, IndexType
    from seqsetup.models.sample import Sample
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=InstrumentPlatform.MISEQ,
                        flowcell_type="v3",
                        run_cycles=RunCycles(151, 151, index_cycles, index_cycles))
    run.add_sample(Sample(sample_id="S1", test_id="A3M", test_version="1", lanes=[1],
                          barcode_mismatches_index1=mismatch_index1,
                          barcode_mismatches_index2=None,
                          index_pair=IndexPair(
                              id="p1", name="p1",
                              index1=Index(name="i7", sequence=i7, index_type=IndexType.I7),
                              index2=Index(name="i5", sequence=i5, index_type=IndexType.I5),
                          )))
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


class TestTheV1DecisionOnTheProfilePath:
    """Mark Ready decides the v1 sheet from the numbers its checks used, which
    on the profile path come from the BCLConvert profile (spec §3; the plan
    review's finding)."""

    def test_a_profile_default_other_than_the_runs_gives_no_v1_sheet(
            self, logged_in_client, miseq_profiles):
        from .conftest import mark_ready
        run = _miseq_profile_draft(miseq_profiles, "a3-v1-profile")
        mark_ready(logged_in_client, run.id, ORIGIN)
        run = miseq_profiles.run_repo.get_by_id(run.id)
        assert run.status == RunStatus.READY
        assert run.generated_samplesheet_v2
        assert run.generated_samplesheet_v1 is None
        assert run.samplesheet_v1_withheld == V1_REASON

    def test_a_sync_during_the_writing_stores_no_v1_sheet(self, logged_in_client, miseq_profiles,
                                                         monkeypatch):
        from .conftest import mark_ready
        run = _miseq_profile_draft(miseq_profiles, "a3-v1-race")
        stored = miseq_profiles.app_profile_repo.list_all()[0]
        _during_the_writing(monkeypatch, lambda: miseq_profiles.app_profile_repo.save(
            _bcl_profile(mismatch_default=1, profile_id=stored.id)))
        resp = mark_ready(logged_in_client, run.id, ORIGIN)
        assert resp.status_code == 409
        run = miseq_profiles.run_repo.get_by_id(run.id)
        assert run.status == RunStatus.DRAFT
        assert run.generated_samplesheet_v1 is None and run.samplesheet_v1_withheld == ""

    def test_an_index_shorter_than_its_read_keeps_its_v1_sheet(self, logged_in_client,
                                                              miseq_profiles):
        # I8N2 with the run's numbers: Mark Ready stores a v1 sheet with the
        # index at 8 bases and no OverrideCycles.
        from .conftest import mark_ready
        run = _miseq_profile_draft(miseq_profiles, "a3-v1-short", index_cycles=10,
                                   mismatch_index1=1)
        run.samples[0].barcode_mismatches_index2 = 1
        miseq_profiles.run_repo.save(run)
        mark_ready(logged_in_client, run.id, ORIGIN)
        run = miseq_profiles.run_repo.get_by_id(run.id)
        assert run.status == RunStatus.READY and run.samplesheet_v1_withheld == ""
        lines = run.generated_samplesheet_v1.splitlines()
        header = lines[lines.index("[Data]") + 1].split(",")
        row = dict(zip(header, lines[lines.index("[Data]") + 2].split(",")))
        assert (row["index"], row["index2"]) == ("ATTACTCG", "TATAGCCT")
        assert not any("OverrideCycles" in line for line in lines)



class TestTheCacheClears:
    """The validation cache is cleared after a config sync and after an index
    kit is saved or deleted (CLAUDE.md, Validation cache coherence; spec §5).
    Switched off, no test noticed (2026-10-03 project review, H-3)."""

    def test_after_a_sync_the_checks_see_the_new_profiles(self, fresh_app, monkeypatch):
        from seqsetup.services.validation import ValidationService, clear_validation_cache
        from .test_sheet_followups import _app_profile_yaml, _sync
        _app, ctx, _db = fresh_app
        clear_validation_cache()
        ok, message, _count = _sync(ctx, monkeypatch, {
            "GuardProfile.yaml": _app_profile_yaml("GuardProfile", '"4.3.6"')})
        assert ok, message
        run = _indexed_draft(ctx, "a3-cache", test_id="WGS")

        def profile_errors():
            result = ValidationService.validate_run(
                run, test_profile_repo=ctx.test_profile_repo,
                app_profile_repo=ctx.app_profile_repo, instrument_config=ctx.instrument_config)
            return [e.error_type for e in result.application_errors]

        assert profile_errors() == []     # cached now
        ok, message, _count = _sync(ctx, monkeypatch, {
            "Other.yaml": _app_profile_yaml("Other", '"4.3.6"')})   # GuardProfile is gone
        assert ok, message
        assert profile_errors() == ["profile_not_found"]

    def _version(self):
        from seqsetup.services.validation import _current_validation_input_version
        return _current_validation_input_version()

    def test_saving_an_index_kit_clears_it(self, logged_in_client, fresh_app):
        before = self._version()
        resp = logged_in_client.post(
            "/indexes/upload",
            data={"index_mode": "unique_dual", "kit_name": "A3Kit", "kit_version": "1.0"},
            files={"index_file": ("a3.yaml", (
                b"index_pairs:\n  - id: A3-P1\n    name: P1\n    index1:\n      name: i7-A01\n"
                b"      sequence: ATTACTCG\n    index2:\n      name: i5-A01\n"
                b"      sequence: TATAGCCT\n"), "text/yaml")},
            headers=ORIGIN,
        )
        assert resp.status_code == 200 and resp.headers.get("HX-Redirect") == "/indexes"
        assert self._version() > before

    def test_deleting_an_index_kit_clears_it(self, logged_in_client, fresh_app):
        from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
        _app, ctx, _db = fresh_app
        ctx.index_kit_repo.save(IndexKit(
            name="A3Gone", version="1.0", index_mode=IndexMode.UNIQUE_DUAL, created_by="admin-test",
            index_pairs=[IndexPair(id="g1", name="G1",
                                   index1=Index(name="i7", sequence="ATTACTCG",
                                                index_type=IndexType.I7),
                                   index2=Index(name="i5", sequence="TATAGCCT",
                                                index_type=IndexType.I5))]))
        before = self._version()
        resp = logged_in_client.delete("/indexes/kits/A3Gone/1.0", headers=ORIGIN)
        assert resp.status_code == 200, resp.text[:300]
        assert ctx.index_kit_repo.get_by_name_and_version("A3Gone", "1.0") is None
        assert self._version() > before


def _two_sample_draft(ctx, run_id, first, second):
    """A NovaSeq X draft with two samples in lane 1; each is (i7, i5 or None)."""
    from seqsetup.models.index import Index, IndexPair, IndexType
    from seqsetup.models.sample import Sample
    from .conftest import disable_repos
    disable_repos(ctx, "test_profile", "app_profile")
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
    for n, (i7, i5) in enumerate((first, second), start=1):
        sample = Sample(sample_id=f"S{n}", lanes=[1])
        if i5 is None:
            sample.assign_index1(Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7))
        else:
            sample.index_pair = IndexPair(
                id=f"p{n}", name=f"p{n}",
                index1=Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7),
                index2=Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5))
        run.add_sample(sample)
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


class TestMarkReadyRefusesTheUntestedRules:
    """Mark Ready refuses on each of the rules no test checked (spec §5)."""

    @pytest.mark.parametrize("first,second,said", [
        pytest.param(("ACGTACGT", "TTGGCCAATT"), ("TGCATGCAAC", "CCAATTGGTT"),
                     "Lane 1: i7 index lengths are inconsistent", id="i7-length"),
        pytest.param(("ACGTACGTAC", "TTGGCCAA"), ("TGCATGCAAC", "CCAATTGGTT"),
                     "Lane 1: i5 index lengths are inconsistent", id="i5-length"),
        pytest.param(("ACGTACGTAC", "TTGGCCAATT"), ("TGCATGCAAC", None),
                     "Lane 1: mixed single-indexed (1 samples) and dual-indexed (1 samples)",
                     id="mixed-indexing"),
        pytest.param(("GGTACGTACG", "TTGGCCAATT"), ("TGCATGCAAC", "CCAATTGGTT"),
                     "S1: i7 index (GGTACGTACG) starts with two dark bases (GG)",
                     id="i7-dark-start"),
    ])
    def test_it_refuses(self, logged_in_client, fresh_app, first, second, said):
        _app, ctx, _db = fresh_app
        run = _two_sample_draft(ctx, "a3-rule", first, second)

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert said in html.unescape(resp.text)
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.DRAFT

    def test_a_version_the_instrument_does_not_have(self, logged_in_client, profiles):
        stored = profiles.app_profile_repo.list_all()[0]
        bumped = _bcl_profile(profile_id=stored.id)
        bumped.settings = {"SoftwareVersion": "9.9.9"}
        profiles.app_profile_repo.save(bumped)
        run = _indexed_draft(profiles, "a3-version", test_id="A3T")

        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert "Application 'BCLConvert' version '9.9.9'" in html.unescape(resp.text)
        assert profiles.run_repo.get_by_id(run.id).status == RunStatus.DRAFT
