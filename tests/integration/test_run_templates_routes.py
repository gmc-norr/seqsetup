"""Integration tests for clone + template routes."""

import json

import pytest

from seqsetup.models.run_template import RunTemplate
from seqsetup.models.sequencing_run import RunStatus

from .conftest import nothing_stored, seed_stored_exports


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _create_run(client) -> str:
    r = client.post("/runs/new", follow_redirects=False, headers=_origin())
    assert r.status_code == 303, r.text[:300]
    return r.headers["location"].split("run_id=", 1)[1].split("&", 1)[0]


def _add_sample(client, run_id, sample_id="S1"):
    r = client.post(
        f"/runs/{run_id}/samples", data={"sample_id": sample_id}, headers=_origin()
    )
    assert r.status_code == 200


class TestCloneRun:
    def test_duplicate_config_only_creates_draft_without_samples(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        before = len(ctx.run_repo.list_all())

        r = logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "false"},
            headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        assert len(ctx.run_repo.list_all()) == before + 1

        new_run = ctx.run_repo.get_by_id(new_id)
        assert new_run.status == RunStatus.DRAFT
        assert new_run.samples == []
        assert nothing_stored(ctx, new_run)

    def test_duplicate_include_samples_copies_samples(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")

        r = logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "true"},
            headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        new_run = ctx.run_repo.get_by_id(new_id)
        assert [s.sample_id for s in new_run.samples] == ["S1"]

    def test_duplicate_does_not_mutate_source(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "true"}, headers=_origin(),
            follow_redirects=False,
        )
        src = ctx.run_repo.get_by_id(run_id)
        assert len(src.samples) == 1
        assert src.status == RunStatus.DRAFT

    def test_duplicate_missing_run_404(self, logged_in_client):
        r = logged_in_client.post(
            "/runs/does-not-exist/duplicate",
            data={"include_samples": "false"}, headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 404


SETUP_ONLY = "A template holds a run's setup only, not its samples. Nothing was saved."


class TestATemplateHoldsNoSamples:
    """The user's choice (2026-10-15): a template is a run's setup only. The
    page never sent samples (its hidden scaffold_sample_ids is "[]"), but the
    route took a list from any request and stored those samples with their
    indexes, to copy into every run made from the template -- a way to copy
    indexes nothing checked. A request naming samples is now refused."""

    def _run_with_a_sample(self, client, ctx):
        run_id = _create_run(client)
        _add_sample(client, run_id, "CTRL_POS")
        return run_id, ctx.run_repo.get_by_id(run_id).samples[0].id

    def _save(self, client, run_id, **fields):
        return client.post(f"/runs/{run_id}/save-as-template",
                           data={"name": "WGS Standard", "description": "std", **fields},
                           headers=_origin(), follow_redirects=False)

    def test_a_request_naming_samples_is_refused_and_saves_nothing(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id, sample_uuid = self._run_with_a_sample(logged_in_client, ctx)

        r = self._save(logged_in_client, run_id, scaffold_sample_ids=json.dumps([sample_uuid]))

        assert (r.status_code, r.text) == (400, SETUP_ONLY)
        assert ctx.run_template_repo.list_all() == []

    def test_a_sample_id_the_run_does_not_hold_is_refused_too(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id, _sample_uuid = self._run_with_a_sample(logged_in_client, ctx)

        r = self._save(logged_in_client, run_id, scaffold_sample_ids=json.dumps(["not-a-sample"]))

        assert (r.status_code, r.text) == (400, SETUP_ONLY)
        assert ctx.run_template_repo.list_all() == []

    @pytest.mark.parametrize("value", ['"CTRL_POS"', '{"CTRL_POS": 1}', "5", "null"])
    def test_a_sample_list_that_is_not_a_list_is_refused(
            self, logged_in_client, fresh_app, value):
        _app, ctx, _db = fresh_app
        run_id, _sample_uuid = self._run_with_a_sample(logged_in_client, ctx)

        r = self._save(logged_in_client, run_id, scaffold_sample_ids=value)

        assert (r.status_code, r.text) == (400, "Invalid scaffold_sample_ids")
        assert ctx.run_template_repo.list_all() == []

    @pytest.mark.parametrize("named_first", [False, True],
                             ids=["named list last", "named list first"])
    def test_the_sample_list_sent_twice_is_refused(
            self, logged_in_client, fresh_app, named_first):
        """Review P3 (2026-10-15): the route read only the last of two
        values, so a named list followed by "[]" saved as if none was sent."""
        _app, ctx, _db = fresh_app
        run_id, sample_uuid = self._run_with_a_sample(logged_in_client, ctx)
        named = json.dumps([sample_uuid])

        r = self._save(logged_in_client, run_id,
                       scaffold_sample_ids=[named, "[]"] if named_first else ["[]", named])

        assert (r.status_code, r.text) == (400, "Invalid scaffold_sample_ids")
        assert ctx.run_template_repo.list_all() == []

    def test_a_sample_list_nested_too_deep_to_read_is_refused(
            self, logged_in_client, fresh_app):
        """Review P3 (2026-10-15): Python's json gives up on a list nested
        100,000 deep with a RecursionError, which answered 500."""
        _app, ctx, _db = fresh_app
        run_id, _sample_uuid = self._run_with_a_sample(logged_in_client, ctx)
        deep = "[" * 100_000 + "]" * 100_000

        r = logged_in_client.post(f"/runs/{run_id}/save-as-template",
                                  data={"name": "WGS Standard", "description": ""},
                                  files={"scaffold_sample_ids": (None, deep)},
                                  headers=_origin(), follow_redirects=False)

        assert (r.status_code, r.text) == (400, "Invalid scaffold_sample_ids")
        assert ctx.run_template_repo.list_all() == []

    @pytest.mark.parametrize("fields", [{"scaffold_sample_ids": "[]"}, {}],
                             ids=["empty list, as the page sends", "no list"])
    def test_the_setup_alone_is_saved(self, logged_in_client, fresh_app, fields):
        _app, ctx, _db = fresh_app
        run_id, _sample_uuid = self._run_with_a_sample(logged_in_client, ctx)
        run = ctx.run_repo.get_by_id(run_id)

        r = self._save(logged_in_client, run_id, **fields)

        assert r.status_code == 303
        (t,) = ctx.run_template_repo.list_all()
        assert (t.name, t.flowcell_type, t.scaffold_samples) == (
            "WGS Standard", run.flowcell_type, [])


class TestSaveAsTemplate:

    def test_save_as_template_with_no_scaffold_is_config_only(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "Config Only", "description": "", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        t = ctx.run_template_repo.list_all()[0]
        assert t.scaffold_samples == []

    def test_save_as_template_requires_name(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "  ", "description": "", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 400
        assert ctx.run_template_repo.list_all() == []

    def test_save_as_template_is_create_only(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        for _ in range(2):
            logged_in_client.post(
                f"/runs/{run_id}/save-as-template",
                data={"name": "Dup", "description": "", "scaffold_sample_ids": "[]"},
                headers=_origin(), follow_redirects=False,
            )
        # Two saves with the same name -> two distinct templates.
        assert len(ctx.run_template_repo.list_all()) == 2

    def _run_with_analysis(self, logged_in_client, ctx, sample_ids):
        from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
        run_id = _create_run(logged_in_client)
        _add_sample(logged_in_client, run_id, "S1")
        _add_sample(logged_in_client, run_id, "CTRL_POS")
        run = ctx.run_repo.get_by_id(run_id)
        run.analyses = [Analysis(
            name="g", analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE, sample_ids=sample_ids,
        )]
        ctx.run_repo.save(run)
        ctrl = next(s for s in run.samples if s.sample_id == "CTRL_POS")
        return run_id, ctrl.id

    def test_save_as_template_drops_the_runs_analyses(
        self, logged_in_client, fresh_app
    ):
        # A template holds no samples (TestATemplateHoldsNoSamples), so no
        # analysis has a sample left to name: each is dropped.
        _app, ctx, _db = fresh_app
        run_id, _ctrl_id = self._run_with_analysis(
            logged_in_client, ctx, ["S1", "CTRL_POS"]
        )
        r = logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "Dropped", "description": "", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        t = ctx.run_template_repo.list_all()[0]
        assert t.analyses == []


class TestTemplateCrud:
    def _make_template(self, logged_in_client, ctx) -> str:
        run_id = _create_run(logged_in_client)
        logged_in_client.post(
            f"/runs/{run_id}/save-as-template",
            data={"name": "Orig", "description": "d", "scaffold_sample_ids": "[]"},
            headers=_origin(), follow_redirects=False,
        )
        return ctx.run_template_repo.list_all()[0].id

    def test_list_page_renders_template(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        self._make_template(logged_in_client, ctx)
        r = logged_in_client.get("/templates")
        assert r.status_code == 200
        assert "Orig" in r.text

    def test_edit_updates_name_description_and_touches(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        tid = self._make_template(logged_in_client, ctx)
        before = ctx.run_template_repo.get_by_id(tid).updated_at
        r = logged_in_client.post(
            f"/templates/{tid}",
            data={"name": "Renamed", "description": "new"},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        t = ctx.run_template_repo.get_by_id(tid)
        assert t.name == "Renamed"
        assert t.description == "new"
        assert t.updated_at >= before
        assert t.updated_by  # actor recorded

    def test_delete_removes_template(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = self._make_template(logged_in_client, ctx)
        r = logged_in_client.delete(f"/templates/{tid}", headers=_origin())
        assert r.status_code in (200, 204)
        assert ctx.run_template_repo.get_by_id(tid) is None

    def test_template_never_appears_in_run_repo(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        self._make_template(logged_in_client, ctx)
        # The save-as-template flow created exactly one run (the source);
        # the template is NOT a run.
        assert len(ctx.run_repo.list_all()) == 1

    def test_edit_missing_template_404(self, logged_in_client, fresh_app):
        r = logged_in_client.post(
            "/templates/nope",
            data={"name": "x", "description": ""},
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 404

    def test_delete_missing_template_404(self, logged_in_client, fresh_app):
        r = logged_in_client.delete("/templates/nope", headers=_origin())
        assert r.status_code == 404


class TestCreateFromTemplate:
    def _make_template_with_scaffold(self, logged_in_client, ctx) -> str:
        """A template stored with a sample, as one saved before a template
        held the setup only (TestATemplateHoldsNoSamples): the route no
        longer makes one, and such a template still makes its run."""
        from seqsetup.models.index import Index, IndexPair, IndexType
        from seqsetup.models.sample import Sample
        run_id = _create_run(logged_in_client)
        run = ctx.run_repo.get_by_id(run_id)
        pair = IndexPair(id="OldKit_P1", name="P1",
                         index1=Index("P1", "ACGTACGT", IndexType.I7),
                         index2=Index("P1", "TTGGCCAA", IndexType.I5))
        template = RunTemplate(name="WithCtrl", instrument_platform=run.instrument_platform,
                               flowcell_type=run.flowcell_type,
                               reagent_cycles=run.reagent_cycles, run_cycles=run.run_cycles,
                               scaffold_samples=[Sample(sample_id="CTRL_POS", lanes=[2],
                                                        index_pair=pair)])
        ctx.run_template_repo.save(template)
        return template.id

    def test_from_template_creates_draft_with_scaffold(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        tid = self._make_template_with_scaffold(logged_in_client, ctx)
        r = logged_in_client.post(
            f"/runs/new/from-template/{tid}",
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        new_run = ctx.run_repo.get_by_id(new_id)
        assert new_run.status == RunStatus.DRAFT
        assert new_run.run_name == "WithCtrl"
        # The sample keeps exactly the indexes and lanes it was stored with
        # (review P3, 2026-10-15: only its ID was checked).
        assert [(s.sample_id, s.index1_sequence, s.index2_sequence, s.lanes)
                for s in new_run.samples] == [("CTRL_POS", "ACGTACGT", "TTGGCCAA", [2])]
        assert nothing_stored(ctx, new_run)

    def test_from_template_refuses_stale_reference(
        self, logged_in_client, fresh_app, monkeypatch
    ):
        # Empty flowcell set => instrument no longer available; this proves
        # the route wires check_references=True and turns RunInstantiationError
        # into a 400. (The three distinct refusal branches are unit-tested in
        # tests/unit/test_run_builder.py::TestAssertReferencesAvailable.)
        _app, ctx, _db = fresh_app
        tid = self._make_template_with_scaffold(logged_in_client, ctx)
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_flowcells_for_instrument",
            lambda platform, cfg=None: {},
        )
        r = logged_in_client.post(
            f"/runs/new/from-template/{tid}",
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 400
        assert "no longer available" in r.text.lower()

    def test_from_template_missing_template_404(self, logged_in_client):
        r = logged_in_client.post(
            "/runs/new/from-template/nope",
            headers=_origin(), follow_redirects=False,
        )
        assert r.status_code == 404


class TestUiHooks:
    def test_dashboard_shows_duplicate_action(self, logged_in_client, fresh_app):
        run_id = _create_run(logged_in_client)
        r = logged_in_client.get("/")
        assert r.status_code == 200
        assert f"/runs/{run_id}/duplicate" in r.text

    def test_edit_page_shows_save_as_template(self, logged_in_client, fresh_app):
        run_id = _create_run(logged_in_client)
        r = logged_in_client.get(f"/runs/{run_id}")
        assert r.status_code == 200
        assert "save-as-template" in r.text


class TestSafetyBoundaries:
    """Clinical invariants that must not regress: a malicious/invalid scaffold
    cannot bypass model validation, and a clone never resurrects a non-DRAFT
    status or stale exports from its source."""

    def test_non_acgtn_index_in_template_dict_is_rejected(self):
        # Deserializing a template whose scaffold sample carries a non-ACGTN
        # index must RAISE, not silently produce a valid-looking template.
        # Index.__post_init__ rejects characters outside [ACGTN].
        bad = {
            "id": "t1",
            "name": "evil",
            "instrument_platform": "NovaSeq X Series",
            "scaffold_samples": [{
                "id": "x", "sample_id": "S1",
                "index1": {"name": "i", "sequence": "ZZZZ", "index_type": "i7"},
            }],
        }
        with pytest.raises(ValueError):
            RunTemplate.from_dict(bad)

    def test_clone_of_archived_run_does_not_resurrect_status(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.ARCHIVED
        run.exports = seed_stored_exports(ctx, run_id, samplesheet_v2="snapshot")
        ctx.run_repo.save(run)

        r = logged_in_client.post(
            f"/runs/{run_id}/duplicate",
            data={"include_samples": "true"}, headers=_origin(),
            follow_redirects=False,
        )
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        new_run = ctx.run_repo.get_by_id(new_id)
        assert new_run.status == RunStatus.DRAFT
        assert nothing_stored(ctx, new_run)
